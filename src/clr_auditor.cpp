#include "vmemscan/clr_auditor.hpp"

#include <psapi.h>
#include <tlhelp32.h>
#include <cstring>

namespace vmemscan {

std::wstring ClrAuditor::anomaly_type_to_string(ClrAnomalyType type) {
    switch (type) {
    case ClrAnomalyType::UnmanagedProcessClrLoaded:
        return L"Native Process Hosted CLR (execute-assembly / Donut injection indicator)";
    case ClrAnomalyType::InMemoryDotNetAssembly:
        return L"In-Memory .NET Assembly (BSJB metadata in unbacked memory)";
    case ClrAnomalyType::RwxJitHeap:
        return L"CLR JIT Code Heap Allocated with RWX Permissions";
    default:
        return L"Unknown";
    }
}

static bool check_if_process_originally_managed(HANDLE hProcess) {
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded) || cbNeeded == 0) {
        return false;
    }

    HMODULE hMain = hMods[0];
    uint64_t main_base = reinterpret_cast<uint64_t>(hMain);

    IMAGE_DOS_HEADER dos{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(main_base), &dos, sizeof(dos), &read) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000) {
        return false;
    }

    IMAGE_NT_HEADERS64 nth{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(main_base + dos.e_lfanew), &nth, sizeof(nth), &read)) {
        return false;
    }

    if (nth.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const auto& com_dir = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    return (com_dir.VirtualAddress != 0 && com_dir.Size > 0);
}

ClrAuditReport ClrAuditor::audit_process(HANDLE hProcess, uint32_t pid) {
    ClrAuditReport report{};
    report.process_id = pid;

    if (!hProcess || pid == 0) {
        return report;
    }

    report.is_originally_managed = check_if_process_originally_managed(hProcess);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        if (Module32FirstW(hSnap, &me)) {
            do {
                if (_wcsicmp(me.szModule, L"clr.dll") == 0 ||
                    _wcsicmp(me.szModule, L"coreclr.dll") == 0 ||
                    _wcsicmp(me.szModule, L"mscorwks.dll") == 0) {
                    report.has_clr_runtime = true;
                    report.clr_module_name = me.szModule;
                    report.clr_module_base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                    break;
                }
            } while (Module32NextW(hSnap, &me));
        }
        CloseHandle(hSnap);
    }

    // If an unmanaged native application loaded CLR runtime, flag it
    if (!report.is_originally_managed && report.has_clr_runtime) {
        ClrAnomaly ca{};
        ca.address = report.clr_module_base;
        ca.size = 0;
        ca.anomaly_type = ClrAnomalyType::UnmanagedProcessClrLoaded;
        ca.description = L"Native Win32 process loaded CLR (" + report.clr_module_name + L") without .NET COM directory";
        report.anomalies.push_back(ca);
    }

    // Memory scan for unbacked in-memory .NET assemblies (BSJB metadata header: 0x424A5342)
    const uint32_t BSJB_MAGIC = 0x424A5342;
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);

    uint8_t* p = static_cast<uint8_t*>(si.lpMinimumApplicationAddress);
    uint8_t* max_addr = static_cast<uint8_t*>(si.lpMaximumApplicationAddress);

    while (p < max_addr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProcess, p, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            break;
        }

        if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)) {
            // Check for RWX JIT heap
            if (report.has_clr_runtime && mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize >= 0x1000) {
                ClrAnomaly ca{};
                ca.address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                ca.size = mbi.RegionSize;
                ca.anomaly_type = ClrAnomalyType::RwxJitHeap;
                ca.description = L"Potential RWX JIT code heap in unbacked private memory";
                ca.memory_protection = mbi.Protect;
                ca.memory_type = mbi.Type;
                report.anomalies.push_back(ca);
            }

            // Scan for BSJB signature in readable committed pages
            if ((mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0 &&
                !(mbi.Protect & PAGE_GUARD)) {
                size_t scan_size = mbi.RegionSize;
                if (scan_size > 4 * 1024 * 1024) {
                    scan_size = 4 * 1024 * 1024; // Limit to 4MB per region for efficiency
                }

                std::vector<uint8_t> buffer(scan_size);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), scan_size, &bytes_read) && bytes_read >= 32) {
                    for (size_t i = 0; i + 32 <= bytes_read; i += 4) {
                        uint32_t val = *reinterpret_cast<const uint32_t*>(buffer.data() + i);
                        if (val == BSJB_MAGIC) {
                            // Validate BSJB metadata header
                            // Offset +12: Version length (DWORD)
                            uint32_t ver_len = *reinterpret_cast<const uint32_t*>(buffer.data() + i + 12);
                            if (ver_len >= 4 && ver_len <= 64 && i + 16 + ver_len <= bytes_read) {
                                std::string ver_str(reinterpret_cast<const char*>(buffer.data() + i + 16), ver_len);
                                // Check if ver_str starts with "v1." or "v2." or "v4."
                                if (ver_str.rfind("v", 0) == 0) {
                                    // Remove trailing null bytes or padding
                                    while (!ver_str.empty() && (ver_str.back() == '\0' || ver_str.back() == ' ')) {
                                        ver_str.pop_back();
                                    }

                                    ++report.in_memory_assemblies_count;

                                    ClrAnomaly ca{};
                                    ca.address = reinterpret_cast<uint64_t>(mbi.BaseAddress) + i;
                                    ca.size = mbi.RegionSize;
                                    ca.anomaly_type = ClrAnomalyType::InMemoryDotNetAssembly;
                                    ca.description = L"In-memory loaded .NET assembly metadata (BSJB) version: " +
                                                     std::wstring(ver_str.begin(), ver_str.end());
                                    ca.clr_version = ver_str;
                                    ca.memory_protection = mbi.Protect;
                                    ca.memory_type = mbi.Type;
                                    report.anomalies.push_back(ca);
                                    break; // Only report once per region
                                }
                            }
                        }
                    }
                }
            }
        }

        p += mbi.RegionSize;
    }

    return report;
}

} // namespace vmemscan
