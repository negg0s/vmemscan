#include "vmemscan/veh_auditor.hpp"
#include "vmemscan/memory_scanner.hpp"
#include "vmemscan/nt_defs.hpp"

#include <algorithm>

namespace vmemscan {

std::vector<VehAnomaly> VehAuditor::scan_regions_for_guard_traps(
    const std::vector<MemoryRegion>& regions
) {
    std::vector<VehAnomaly> anomalies;

    for (const auto& r : regions) {
        if (r.state != MEM_COMMIT) {
            continue;
        }

        // Check for PAGE_GUARD protection flag
        if ((r.protect & PAGE_GUARD) != 0) {
            // Executable page marked with PAGE_GUARD: direct signature of Page Guard Hooking / VEH Trapping
            if (r.is_executable) {
                VehAnomaly a{};
                a.target_address = r.base_address;
                a.anomaly_type = L"PAGE_GUARD Executable Trap";
                a.mapped_module = r.mapped_file;
                a.memory_protection = r.protect;
                a.protection_string = MemoryScanner::protect_to_string(r.protect);
                a.is_unbacked = r.is_unbacked_executable;
                a.is_rwx = r.is_rwx;
                a.is_guard_page_trap = true;
                a.details = L"Executable memory region marked with PAGE_GUARD (STATUS_GUARD_PAGE_VIOLATION trap for VEH hooking / execution diversion)";
                anomalies.push_back(std::move(a));
            } else if (r.type == MEM_PRIVATE && r.region_size > 65536) {
                // Large private data region with PAGE_GUARD (outside typical single-page stack guard)
                VehAnomaly a{};
                a.target_address = r.base_address;
                a.anomaly_type = L"PAGE_GUARD Large Private Region Trap";
                a.mapped_module = r.mapped_file;
                a.memory_protection = r.protect;
                a.protection_string = MemoryScanner::protect_to_string(r.protect);
                a.is_unbacked = true;
                a.is_rwx = false;
                a.is_guard_page_trap = true;
                a.details = L"Large private memory block (" + MemoryScanner::protect_to_string(r.protect) +
                            L") armed with PAGE_GUARD trap modifier (Memory access hook / evasion)";
                anomalies.push_back(std::move(a));
            }
        }
    }

    return anomalies;
}

VehAuditReport VehAuditor::audit_process_veh(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    VehAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;
    rep.regions_evaluated = regions.size();

    if (!hProcess || pid == 0) {
        return rep;
    }

    // 1. Scan memory regions for active PAGE_GUARD traps
    auto traps = scan_regions_for_guard_traps(regions);
    for (auto& t : traps) {
        if (t.is_guard_page_trap) {
            ++rep.guard_page_traps_count;
        }
        rep.anomalies.push_back(std::move(t));
    }

    // 2. Query UnhandledExceptionFilter in target process
    // In KERNELBASE.dll, BasepCurrentTopLevelFilter holds the top-level exception handler
    HMODULE hKb = GetModuleHandleW(L"kernelbase.dll");
    if (!hKb) hKb = GetModuleHandleW(L"kernel32.dll");

    if (hKb) {
        // Query SetUnhandledExceptionFilter entry point
        auto pfnSet = reinterpret_cast<uint64_t>(GetProcAddress(hKb, "SetUnhandledExceptionFilter"));
        if (pfnSet != 0) {
            // Read first 32 bytes of SetUnhandledExceptionFilter to extract pointer to BasepCurrentTopLevelFilter
            uint8_t code[32]{0};
            SIZE_T read = 0;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(pfnSet), code, sizeof(code), &read) && read >= 16) {
                // On x64, SetUnhandledExceptionFilter typically moves old filter:
                // 48 8B 05 xx xx xx xx (MOV RAX, [RIP + rel32]) or 48 87 05 xx xx xx xx (XCHG RAX, [RIP + rel32])
                for (size_t i = 0; i + 7 <= read; ++i) {
                    if (code[i] == 0x48 && (code[i + 1] == 0x8B || code[i + 1] == 0x87) && code[i + 2] == 0x05) {
                        int32_t rel = 0;
                        std::memcpy(&rel, &code[i + 3], sizeof(int32_t));
                        uint64_t filter_var_addr = pfnSet + i + 7 + rel;

                        uint64_t current_handler = 0;
                        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(filter_var_addr), &current_handler, sizeof(current_handler), &read) && current_handler != 0) {
                            // Check which memory region current_handler belongs to
                            for (const auto& r : regions) {
                                if (current_handler >= r.base_address && current_handler < r.base_address + r.region_size) {
                                    if (r.is_unbacked_executable || r.is_rwx || r.type == MEM_PRIVATE) {
                                        VehAnomaly a{};
                                        a.target_address = current_handler;
                                        a.anomaly_type = L"Hijacked Top-Level Exception Filter";
                                        a.mapped_module = r.mapped_file;
                                        a.memory_protection = r.protect;
                                        a.protection_string = MemoryScanner::protect_to_string(r.protect);
                                        a.is_unbacked = r.is_unbacked_executable;
                                        a.is_rwx = r.is_rwx;
                                        a.details = L"BasepCurrentTopLevelFilter redirected to unbacked private memory (Custom crash/exception hook)";
                                        rep.anomalies.push_back(std::move(a));
                                        ++rep.anomalous_handlers_count;
                                    }
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    return rep;
}

} // namespace vmemscan
