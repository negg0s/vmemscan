#include "vmemscan/module_auditor.hpp"
#include "vmemscan/nt_defs.hpp"

#include <tlhelp32.h>
#include <unordered_map>

namespace vmemscan {

std::wstring ModuleAuditor::anomaly_to_string(ModuleAnomalyType type) {
    switch (type) {
    case ModuleAnomalyType::None:             return L"None";
    case ModuleAnomalyType::UnlinkedFromPeb:  return L"Unlinked from PEB (Stealth In-Memory Module / Rootkit)";
    case ModuleAnomalyType::SuspiciousPath:   return L"Loaded from Temporary / Untrusted Directory";
    case ModuleAnomalyType::MismatchedPath:   return L"PEB Module Path Mismatched";
    default:                                  return L"Unknown";
    }
}

static bool is_suspicious_path(const std::wstring& path) {
    std::wstring p = path;
    for (auto& c : p) c = static_cast<wchar_t>(towlower(c));

    if (p.find(L"\\temp\\") != std::wstring::npos ||
        p.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
        p.find(L"\\users\\public\\") != std::wstring::npos) {
        return true;
    }
    return false;
}

ModuleAuditReport ModuleAuditor::audit_process_modules(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    bool is_64bit
) {
    ModuleAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || pid == 0) {
        return rep;
    }

    std::unordered_map<uint64_t, LoadedModuleInfo> module_map;

    // 1. Enumerate modules via Toolhelp
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(hSnap, &me)) {
            do {
                uint64_t base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                LoadedModuleInfo info{};
                info.module_name = me.szModule;
                info.module_path = me.szExePath;
                info.base_address = base;
                info.size_of_image = me.modBaseSize;
                info.in_toolhelp_list = true;
                if (is_suspicious_path(info.module_path)) {
                    info.anomalies.push_back(ModuleAnomalyType::SuspiciousPath);
                }
                module_map[base] = std::move(info);
            } while (Module32NextW(hSnap, &me));
        }
        CloseHandle(hSnap);
    }

    // 2. Enumerate modules via PEB Ldr list (64-bit processes)
    if (is_64bit) {
        auto pfnQuery = NtApiLoader::get_nt_query_information_process();
        if (pfnQuery) {
            PROCESS_BASIC_INFORMATION pbi{};
            ULONG ret_len = 0;
            if (pfnQuery(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len) == 0 && pbi.PebBaseAddress) {
                uint64_t peb_addr = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);
                uint64_t ldr_ptr = 0;
                SIZE_T read = 0;

                // Read PEB.Ldr pointer at offset 0x18
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(peb_addr + 0x18), &ldr_ptr, sizeof(ldr_ptr), &read) && ldr_ptr) {
                    // Read InLoadOrderModuleList at offset 0x10 of PEB_LDR_DATA
                    LIST_ENTRY head{};
                    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(ldr_ptr + 0x10), &head, sizeof(head), &read)) {
                        uint64_t current = reinterpret_cast<uint64_t>(head.Flink);
                        uint64_t head_addr = ldr_ptr + 0x10;
                        size_t visited = 0;

                        while (current && current != head_addr && visited < 500) {
                            ++visited;

                            // Read LDR_DATA_TABLE_ENTRY fields
                            uint64_t dll_base = 0;
                            uint32_t size_of_image = 0;
                            UNICODE_STRING base_name_str{};
                            UNICODE_STRING full_name_str{};

                            ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(current + 0x30), &dll_base, sizeof(dll_base), &read);
                            ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(current + 0x40), &size_of_image, sizeof(size_of_image), &read);
                            ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(current + 0x48), &full_name_str, sizeof(full_name_str), &read);
                            ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(current + 0x58), &base_name_str, sizeof(base_name_str), &read);

                            std::wstring base_name;
                            if (base_name_str.Length > 0 && base_name_str.Buffer) {
                                std::vector<wchar_t> name_buf((base_name_str.Length / sizeof(wchar_t)) + 1, 0);
                                if (ReadProcessMemory(hProcess, base_name_str.Buffer, name_buf.data(), base_name_str.Length, &read)) {
                                    base_name = name_buf.data();
                                }
                            }

                            std::wstring full_name;
                            if (full_name_str.Length > 0 && full_name_str.Buffer) {
                                std::vector<wchar_t> path_buf((full_name_str.Length / sizeof(wchar_t)) + 1, 0);
                                if (ReadProcessMemory(hProcess, full_name_str.Buffer, path_buf.data(), full_name_str.Length, &read)) {
                                    full_name = path_buf.data();
                                }
                            }

                            if (dll_base != 0) {
                                auto it = module_map.find(dll_base);
                                if (it != module_map.end()) {
                                    it->second.in_peb_list = true;
                                } else {
                                    // Module found in PEB but missing in Toolhelp
                                    LoadedModuleInfo info{};
                                    info.module_name = base_name;
                                    info.module_path = full_name;
                                    info.base_address = dll_base;
                                    info.size_of_image = size_of_image;
                                    info.in_peb_list = true;
                                    info.in_toolhelp_list = false;
                                    if (is_suspicious_path(info.module_path)) {
                                        info.anomalies.push_back(ModuleAnomalyType::SuspiciousPath);
                                    }
                                    module_map[dll_base] = std::move(info);
                                }
                            }

                            // Read next Flink
                            LIST_ENTRY next_link{};
                            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(current), &next_link, sizeof(next_link), &read)) {
                                break;
                            }
                            current = reinterpret_cast<uint64_t>(next_link.Flink);
                        }
                    }
                }
            }
        }
    }

    // 3. Detect unlinked modules (present in Toolhelp/memory but missing in PEB)
    for (auto& pair : module_map) {
        auto& mod = pair.second;
        if (is_64bit && mod.in_toolhelp_list && !mod.in_peb_list) {
            mod.anomalies.push_back(ModuleAnomalyType::UnlinkedFromPeb);
        }

        if (!mod.anomalies.empty()) {
            ++rep.anomalous_modules_count;
        }

        rep.modules.push_back(mod);
    }

    rep.total_modules = rep.modules.size();
    return rep;
}

} // namespace vmemscan
