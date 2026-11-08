#include "vmemscan/ldr_auditor.hpp"
#include "vmemscan/nt_defs.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace vmemscan {

// 64-bit explicit PEB Ldr layout
struct VmemPebLdrData64 {
    ULONG Length;
    UCHAR Initialized;
    UCHAR Padding1[3];
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;           // 0x10
    LIST_ENTRY InMemoryOrderModuleList;         // 0x20
    LIST_ENTRY InInitializationOrderModuleList; // 0x30
};

struct VmemLdrEntry64 {
    LIST_ENTRY InLoadOrderLinks;                // 0x00
    LIST_ENTRY InMemoryOrderLinks;              // 0x10
    LIST_ENTRY InInitializationOrderLinks;      // 0x20
    PVOID DllBase;                              // 0x30
    PVOID EntryPoint;                           // 0x38
    ULONG SizeOfImage;                          // 0x40
    ULONG Padding;
    UNICODE_STRING FullDllName;                 // 0x48
    UNICODE_STRING BaseDllName;                 // 0x58
};

std::wstring LdrAuditor::anomaly_type_to_string(LdrAnomalyType type) {
    switch (type) {
    case LdrAnomalyType::None:           return L"None";
    case LdrAnomalyType::UnlinkedModule: return L"Unlinked PE Image (Hidden from PEB)";
    case LdrAnomalyType::PhantomEntry:   return L"Phantom PEB Entry (Unmapped / Private Base)";
    case LdrAnomalyType::ListDesync:     return L"PEB LDR Order Desynchronization";
    case LdrAnomalyType::SpoofedPath:    return L"Suspicious Module Path";
    default:                             return L"Unknown";
    }
}

static std::wstring read_remote_unicode_string(HANDLE hProcess, const UNICODE_STRING& us) {
    if (us.Length == 0 || !us.Buffer) {
        return {};
    }
    const size_t char_count = us.Length / sizeof(wchar_t);
    std::vector<wchar_t> buf(char_count + 1, 0);
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, us.Buffer, buf.data(), us.Length, &read) || read == 0) {
        return {};
    }
    return std::wstring(buf.data(), read / sizeof(wchar_t));
}

std::vector<LdrAnomaly> LdrAuditor::evaluate_discrepancies(
    const std::vector<LdrModuleEntry>& peb_modules,
    const std::vector<MemoryRegion>& regions
) {
    std::vector<LdrAnomaly> anomalies;

    // 1. Check for unlinked modules: MEM_IMAGE regions that are not in PEB InLoadOrderModuleList
    for (const auto& reg : regions) {
        // Look for allocation bases of type Image
        if (reg.type != MEM_IMAGE || reg.state != MEM_COMMIT) {
            continue;
        }

        // Only evaluate at allocation base (start of mapped module)
        if (reg.base_address != reg.allocation_base || reg.base_address == 0) {
            continue;
        }

        // Verify if this mapped image has any executable code pages
        // Resource DLLs loaded via LOAD_LIBRARY_AS_IMAGE_RESOURCE / LOAD_LIBRARY_AS_DATAFILE
        // and .winmd metadata files are mapped as MEM_IMAGE without executable sections
        bool has_executable_pages = false;
        for (const auto& sub_reg : regions) {
            if (sub_reg.allocation_base == reg.base_address) {
                if (sub_reg.is_executable || sub_reg.is_rwx || ((sub_reg.protect & 0xF0) != 0)) {
                    has_executable_pages = true;
                    break;
                }
            }
        }

        if (!has_executable_pages) {
            continue; // Benign resource-only image or Windows Runtime metadata
        }

        bool found_in_peb = false;
        for (const auto& mod : peb_modules) {
            if (mod.dll_base == reg.base_address) {
                found_in_peb = true;
                break;
            }
        }

        if (!found_in_peb) {
            LdrAnomaly a{};
            a.type = LdrAnomalyType::UnlinkedModule;
            a.module_base = reg.base_address;
            a.size_of_image = reg.region_size;
            a.module_name = reg.mapped_file.empty() ? L"<unlinked_image>" : reg.mapped_file;
            a.module_path = reg.mapped_file;
            a.is_critical = true;

            std::wostringstream oss;
            oss << L"Mapped MEM_IMAGE region at 0x" << std::hex << reg.base_address
                << L" is omitted from PEB InLoadOrderModuleList (potential stealth injection or manual unlinking)";
            a.anomaly_description = oss.str();
            anomalies.push_back(a);
        }
    }

    // 2. Check for phantom entries: PEB entries whose DllBase does not point to committed MEM_IMAGE
    for (const auto& mod : peb_modules) {
        if (mod.dll_base == 0) {
            continue;
        }

        bool has_valid_image = false;
        for (const auto& reg : regions) {
            if (reg.base_address <= mod.dll_base && mod.dll_base < (reg.base_address + reg.region_size)) {
                if (reg.type == MEM_IMAGE && reg.state == MEM_COMMIT) {
                    has_valid_image = true;
                }
                break;
            }
        }

        if (!has_valid_image) {
            LdrAnomaly a{};
            a.type = LdrAnomalyType::PhantomEntry;
            a.module_base = mod.dll_base;
            a.size_of_image = mod.size_of_image;
            a.module_name = mod.base_dll_name;
            a.module_path = mod.full_dll_name;
            a.is_critical = true;

            std::wostringstream oss;
            oss << L"PEB LDR lists module " << mod.base_dll_name
                << L" at DllBase 0x" << std::hex << mod.dll_base
                << L", but virtual memory is not a committed MEM_IMAGE region (ghost registration)";
            a.anomaly_description = oss.str();
            anomalies.push_back(a);
        }

        // 3. Check for list desynchronization (present in InLoadOrder but absent in InMemoryOrder)
        if (mod.in_load_order && !mod.in_memory_order) {
            LdrAnomaly a{};
            a.type = LdrAnomalyType::ListDesync;
            a.module_base = mod.dll_base;
            a.size_of_image = mod.size_of_image;
            a.module_name = mod.base_dll_name;
            a.module_path = mod.full_dll_name;
            a.is_critical = false;

            std::wostringstream oss;
            oss << L"Module " << mod.base_dll_name
                << L" at 0x" << std::hex << mod.dll_base
                << L" exists in InLoadOrderModuleList but was severed from InMemoryOrderModuleList";
            a.anomaly_description = oss.str();
            anomalies.push_back(a);
        }
    }

    return anomalies;
}

LdrAuditReport LdrAuditor::audit_process_ldr(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions,
    bool is_64bit
) {
    LdrAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || !is_64bit) {
        return rep;
    }

    auto pfnQuery = NtApiLoader::get_nt_query_information_process();
    if (!pfnQuery) {
        return rep;
    }

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG ret_len = 0;
    if (pfnQuery(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len) != 0 || !pbi.PebBaseAddress) {
        return rep;
    }

    // Read Ldr pointer from PEB (offset 0x18 on 64-bit)
    uint64_t peb_addr = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);
    uint64_t ldr_ptr = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(peb_addr + 0x18), &ldr_ptr, sizeof(ldr_ptr), &read) || ldr_ptr == 0) {
        return rep;
    }

    // Read VmemPebLdrData64
    VmemPebLdrData64 ldr_data{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(ldr_ptr), &ldr_data, sizeof(ldr_data), &read)) {
        return rep;
    }

    std::vector<LdrModuleEntry> peb_modules;

    // Traverse InLoadOrderModuleList
    uint64_t head_load = ldr_ptr + offsetof(VmemPebLdrData64, InLoadOrderModuleList);
    uint64_t curr_load = reinterpret_cast<uint64_t>(ldr_data.InLoadOrderModuleList.Flink);
    size_t count = 0;

    while (curr_load != 0 && curr_load != head_load && count < 512) {
        ++count;
        VmemLdrEntry64 entry{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(curr_load), &entry, sizeof(entry), &read)) {
            break;
        }

        LdrModuleEntry mod{};
        mod.dll_base = reinterpret_cast<uint64_t>(entry.DllBase);
        mod.entry_point = reinterpret_cast<uint64_t>(entry.EntryPoint);
        mod.size_of_image = entry.SizeOfImage;
        mod.full_dll_name = read_remote_unicode_string(hProcess, entry.FullDllName);
        mod.base_dll_name = read_remote_unicode_string(hProcess, entry.BaseDllName);
        mod.in_load_order = true;

        peb_modules.push_back(mod);
        curr_load = reinterpret_cast<uint64_t>(entry.InLoadOrderLinks.Flink);
    }

    // Traverse InMemoryOrderModuleList to correlate in_memory_order
    uint64_t head_mem = ldr_ptr + offsetof(VmemPebLdrData64, InMemoryOrderModuleList);
    uint64_t curr_mem = reinterpret_cast<uint64_t>(ldr_data.InMemoryOrderModuleList.Flink);
    count = 0;

    while (curr_mem != 0 && curr_mem != head_mem && count < 512) {
        ++count;
        uint64_t entry_addr = curr_mem - offsetof(VmemLdrEntry64, InMemoryOrderLinks);
        VmemLdrEntry64 entry{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(entry_addr), &entry, sizeof(entry), &read)) {
            break;
        }

        uint64_t dll_base = reinterpret_cast<uint64_t>(entry.DllBase);
        for (auto& m : peb_modules) {
            if (m.dll_base == dll_base) {
                m.in_memory_order = true;
                break;
            }
        }
        curr_mem = reinterpret_cast<uint64_t>(entry.InMemoryOrderLinks.Flink);
    }

    // Traverse InInitializationOrderModuleList
    uint64_t head_init = ldr_ptr + offsetof(VmemPebLdrData64, InInitializationOrderModuleList);
    uint64_t curr_init = reinterpret_cast<uint64_t>(ldr_data.InInitializationOrderModuleList.Flink);
    count = 0;

    while (curr_init != 0 && curr_init != head_init && count < 512) {
        ++count;
        uint64_t entry_addr = curr_init - offsetof(VmemLdrEntry64, InInitializationOrderLinks);
        VmemLdrEntry64 entry{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(entry_addr), &entry, sizeof(entry), &read)) {
            break;
        }

        uint64_t dll_base = reinterpret_cast<uint64_t>(entry.DllBase);
        for (auto& m : peb_modules) {
            if (m.dll_base == dll_base) {
                m.in_init_order = true;
                break;
            }
        }
        curr_init = reinterpret_cast<uint64_t>(entry.InInitializationOrderLinks.Flink);
    }

    rep.peb_modules_count = peb_modules.size();

    // Count mapped image regions
    for (const auto& r : regions) {
        if (r.type == MEM_IMAGE && r.state == MEM_COMMIT && r.base_address == r.allocation_base && r.base_address != 0) {
            ++rep.mapped_images_count;
        }
    }

    rep.anomalies = evaluate_discrepancies(peb_modules, regions);

    for (const auto& a : rep.anomalies) {
        if (a.type == LdrAnomalyType::UnlinkedModule) {
            ++rep.unlinked_count;
        } else if (a.type == LdrAnomalyType::PhantomEntry) {
            ++rep.phantom_count;
        }
    }

    return rep;
}

} // namespace vmemscan
