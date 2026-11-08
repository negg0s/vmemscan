#include "vmemscan/tls_auditor.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace vmemscan {

std::wstring TlsAuditor::anomaly_type_to_string(TlsAnomalyType type) {
    switch (type) {
    case TlsAnomalyType::None:                  return L"None";
    case TlsAnomalyType::UnbackedCallback:      return L"Unbacked Private Memory Callback";
    case TlsAnomalyType::ForeignModuleCallback: return L"Cross-Module TLS Callback Redirection";
    case TlsAnomalyType::RwxCallback:           return L"RWX Page TLS Callback";
    default:                                    return L"Unknown";
    }
}

static std::wstring prot_to_string(uint32_t p) {
    switch (p & 0xFF) {
    case PAGE_NOACCESS:          return L"PAGE_NOACCESS";
    case PAGE_READONLY:          return L"PAGE_READONLY";
    case PAGE_READWRITE:         return L"PAGE_READWRITE";
    case PAGE_WRITECOPY:         return L"PAGE_WRITECOPY";
    case PAGE_EXECUTE:           return L"PAGE_EXECUTE";
    case PAGE_EXECUTE_READ:      return L"PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return L"PAGE_EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return L"PAGE_EXECUTE_WRITECOPY";
    default:                     return L"PAGE_UNKNOWN";
    }
}

std::vector<TlsAnomaly> TlsAuditor::evaluate_tls_module(
    uint64_t module_base,
    uint64_t module_size,
    const std::wstring& module_name,
    const std::vector<uint64_t>& callbacks,
    const std::vector<MemoryRegion>& regions
) {
    std::vector<TlsAnomaly> anomalies;

    for (uint64_t cb : callbacks) {
        if (cb == 0) {
            continue;
        }

        // Find memory region covering callback address
        const MemoryRegion* target_region = nullptr;
        for (const auto& reg : regions) {
            if (reg.base_address <= cb && cb < (reg.base_address + reg.region_size)) {
                target_region = &reg;
                break;
            }
        }

        // Check if callback resides outside the module's mapped image
        bool is_within_module = (cb >= module_base && cb < (module_base + module_size));

        if (!is_within_module) {
            TlsAnomaly a{};
            a.module_base = module_base;
            a.module_name = module_name;
            a.callback_address = cb;

            if (target_region) {
                a.memory_protection = target_region->protect;
                a.protection_string = prot_to_string(target_region->protect);

                if (target_region->type != MEM_IMAGE) {
                    a.type = TlsAnomalyType::UnbackedCallback;
                    a.is_critical = true;
                    std::wostringstream oss;
                    oss << L"TLS callback at 0x" << std::hex << cb
                        << L" targets unbacked " << (target_region->type == MEM_PRIVATE ? L"MEM_PRIVATE" : L"MEM_MAPPED")
                        << L" memory (" << a.protection_string << L")";
                    a.details = oss.str();
                    anomalies.push_back(a);
                    continue;
                } else {
                    // Check if target region belongs to the same binary image
                    if (!module_name.empty() && !target_region->mapped_file.empty() &&
                        _wcsicmp(module_name.c_str(), target_region->mapped_file.c_str()) == 0) {
                        // Same module image mapped across section boundaries
                        continue;
                    }

                    a.type = TlsAnomalyType::ForeignModuleCallback;
                    a.is_critical = false;
                    std::wostringstream oss;
                    oss << L"TLS callback at 0x" << std::hex << cb
                        << L" targets external module " << target_region->mapped_file;
                    a.details = oss.str();
                    anomalies.push_back(a);
                    continue;
                }
            } else {
                a.type = TlsAnomalyType::UnbackedCallback;
                a.is_critical = true;
                std::wostringstream oss;
                oss << L"TLS callback at 0x" << std::hex << cb << L" targets unmapped virtual address";
                a.details = oss.str();
                anomalies.push_back(a);
                continue;
            }
        }

        // Inside module: check for RWX
        if (target_region && target_region->is_rwx) {
            TlsAnomaly a{};
            a.module_base = module_base;
            a.module_name = module_name;
            a.callback_address = cb;
            a.memory_protection = target_region->protect;
            a.protection_string = prot_to_string(target_region->protect);
            a.type = TlsAnomalyType::RwxCallback;
            a.is_critical = true;

            std::wostringstream oss;
            oss << L"TLS callback at 0x" << std::hex << cb << L" resides in PAGE_EXECUTE_READWRITE section";
            a.details = oss.str();
            anomalies.push_back(a);
        }
    }

    return anomalies;
}

TlsAuditReport TlsAuditor::audit_process_tls(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    TlsAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess) {
        return rep;
    }

    // Inspect each committed MEM_IMAGE allocation base
    for (const auto& reg : regions) {
        if (reg.type != MEM_IMAGE || reg.state != MEM_COMMIT) {
            continue;
        }
        if (reg.base_address != reg.allocation_base || reg.base_address == 0) {
            continue;
        }

        IMAGE_DOS_HEADER dos{};
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(reg.base_address), &dos, sizeof(dos), &read) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        IMAGE_NT_HEADERS64 nth{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(reg.base_address + dos.e_lfanew), &nth, sizeof(nth), &read) ||
            nth.Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        const auto& tls_entry = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tls_entry.VirtualAddress == 0 || tls_entry.Size < sizeof(IMAGE_TLS_DIRECTORY64)) {
            continue;
        }

        ++rep.modules_with_tls_count;

        IMAGE_TLS_DIRECTORY64 tls_dir{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(reg.base_address + tls_entry.VirtualAddress), &tls_dir, sizeof(tls_dir), &read)) {
            continue;
        }

        if (tls_dir.AddressOfCallBacks == 0) {
            continue;
        }

        // Read array of callbacks (null-terminated array of 64-bit pointers)
        std::vector<uint64_t> callbacks;
        uint64_t current_cb_ptr = tls_dir.AddressOfCallBacks;

        for (size_t i = 0; i < 64; ++i) {
            uint64_t cb_addr = 0;
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(current_cb_ptr), &cb_addr, sizeof(cb_addr), &read) || cb_addr == 0) {
                break;
            }
            callbacks.push_back(cb_addr);
            current_cb_ptr += sizeof(uint64_t);
        }

        rep.total_callbacks_scanned += callbacks.size();

        uint64_t mod_size = nth.OptionalHeader.SizeOfImage;
        std::wstring mod_name = reg.mapped_file.empty() ? L"<module>" : reg.mapped_file;

        auto module_anomalies = evaluate_tls_module(reg.base_address, mod_size, mod_name, callbacks, regions);
        for (auto& a : module_anomalies) {
            rep.anomalies.push_back(std::move(a));
        }
    }

    rep.anomalous_callbacks_count = rep.anomalies.size();
    return rep;
}

} // namespace vmemscan
