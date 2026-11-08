#include "vmemscan/injection_detector.hpp"
#include "vmemscan/nt_defs.hpp"

#include <tlhelp32.h>
#include <iomanip>
#include <sstream>

namespace vmemscan {

std::wstring InjectionDetector::severity_to_string(AnomalySeverity sev) {
    switch (sev) {
    case AnomalySeverity::Critical: return L"CRITICAL";
    case AnomalySeverity::High:     return L"HIGH";
    case AnomalySeverity::Medium:   return L"MEDIUM";
    case AnomalySeverity::Low:      return L"LOW";
    default:                        return L"INFO";
    }
}

bool InjectionDetector::detect_shellcode_prolog(const uint8_t* data, size_t size) {
    if (data == nullptr || size < 4) return false;

    // Pattern 1: cld; call (FC E8)
    if (data[0] == 0xFC && data[1] == 0xE8) return true;

    // Pattern 2: cld; sub rsp, ... (FC 48 83 EC or FC 48 83 E4)
    if (data[0] == 0xFC && data[1] == 0x48 && data[2] == 0x83) return true;

    // Pattern 3: call next; pop reg (E8 00 00 00 00 58 / 59 / 5B / 5D)
    if (size >= 6 && data[0] == 0xE8 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x00 && data[4] == 0x00) {
        if (data[5] >= 0x58 && data[5] <= 0x5F) return true;
    }

    // Pattern 4: xor rdx, rdx; xor rcx, rcx (48 31 D2 48 31 C9)
    if (size >= 6 && data[0] == 0x48 && data[1] == 0x31 && data[3] == 0x48 && data[4] == 0x31) return true;

    // Pattern 5: push rbp; mov rbp, rsp (55 48 89 E5)
    if (data[0] == 0x55 && data[1] == 0x48 && data[2] == 0x89 && data[3] == 0xE5) return true;

    return false;
}

ProcessInjectionReport InjectionDetector::analyze_process(
    HANDLE hProcess,
    const ProcessInfo& proc,
    const std::vector<MemoryRegion>& regions
) {
    ProcessInjectionReport report{};
    report.pid = proc.pid;
    report.process_name = proc.name;
    report.process_path = proc.path;
    report.is_64bit = proc.is_64bit;

    if (!hProcess) {
        return report;
    }

    // 1. Audit memory regions for unbacked executable and RWX pages
    for (const auto& r : regions) {
        if (!r.is_executable) {
            continue;
        }

        uint8_t buffer[64]{0};
        SIZE_T bytes_read = 0;
        const BOOL read_ok = ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(r.base_address),
            buffer,
            sizeof(buffer),
            &bytes_read
        );

        const bool has_mz = (read_ok && bytes_read >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A); // 'MZ'
        const bool is_shellcode = (read_ok && bytes_read >= 4 && detect_shellcode_prolog(buffer, bytes_read));

        if (r.is_unbacked_executable) {
            InjectionAnomaly anomaly{};
            anomaly.address = r.base_address;
            anomaly.size = r.region_size;
            anomaly.has_pe_header = has_mz;
            anomaly.is_shellcode_signature = is_shellcode;

            if (read_ok && bytes_read > 0) {
                anomaly.header_preview.assign(buffer, buffer + bytes_read);
            }

            if (has_mz) {
                anomaly.severity = AnomalySeverity::Critical;
                anomaly.type_name = L"Reflective PE / In-Memory DLL Injection";
                anomaly.description = L"Committed private memory marked executable contains an intact DOS PE header (MZ)";
                report.has_reflective_pe = true;
                ++report.critical_anomalies_count;
            } else if (r.is_rwx) {
                anomaly.severity = AnomalySeverity::Critical;
                anomaly.type_name = L"Unbacked RWX Memory (Writable & Executable)";
                anomaly.description = L"Private memory marked PAGE_EXECUTE_READWRITE without a backing file on disk";
                if (is_shellcode) {
                    anomaly.details = L"Matches known shellcode prologue pattern";
                }
                ++report.critical_anomalies_count;
            } else {
                anomaly.severity = is_shellcode ? AnomalySeverity::Critical : AnomalySeverity::High;
                anomaly.type_name = L"Unbacked Executable Memory";
                anomaly.description = L"Private or anonymous memory marked executable (code injection / shellcode stager)";
                if (is_shellcode) {
                    anomaly.details = L"Matches shellcode execution prologue pattern";
                    ++report.critical_anomalies_count;
                } else {
                    ++report.high_anomalies_count;
                }
            }

            report.memory_anomalies.push_back(std::move(anomaly));
        } else if (r.is_rwx && r.type == MEM_IMAGE) {
            // RWX in a mapped PE image is an anomaly (unless packed or hooked)
            InjectionAnomaly anomaly{};
            anomaly.severity = AnomalySeverity::High;
            anomaly.type_name = L"Mapped Image RWX Section";
            anomaly.address = r.base_address;
            anomaly.size = r.region_size;
            anomaly.description = L"PE image section modified to PAGE_EXECUTE_READWRITE (in-memory patch or hook)";
            anomaly.details = r.mapped_file;
            if (read_ok && bytes_read > 0) {
                anomaly.header_preview.assign(buffer, buffer + bytes_read);
            }
            ++report.high_anomalies_count;
            report.memory_anomalies.push_back(std::move(anomaly));
        }
    }

    // 2. Audit threads for unbacked execution start addresses
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(THREADENTRY32);

        auto pfnQueryThread = NtApiLoader::get_nt_query_information_thread();

        if (Thread32First(hThreadSnap, &te)) {
            do {
                if (te.th32OwnerProcessID != proc.pid) {
                    continue;
                }

                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!hThread) {
                    hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                }

                if (hThread) {
                    PVOID start_addr = nullptr;
                    ULONG ret_len = 0;

                    if (pfnQueryThread) {
                        NTSTATUS status = pfnQueryThread(
                            hThread,
                            ThreadQuerySetWin32StartAddress,
                            &start_addr,
                            sizeof(start_addr),
                            &ret_len
                        );

                        if (status == 0 && start_addr != nullptr) {
                            const uint64_t u_addr = reinterpret_cast<uint64_t>(start_addr);

                            // Find matching memory region
                            for (const auto& r : regions) {
                                if (u_addr >= r.base_address && u_addr < r.base_address + r.region_size) {
                                    if (r.is_unbacked_executable) {
                                        ThreadAnomaly ta{};
                                        ta.thread_id = te.th32ThreadID;
                                        ta.start_address = u_addr;
                                        ta.region_type = (r.type == MEM_PRIVATE) ? L"MEM_PRIVATE" : L"MEM_MAPPED";
                                        ta.mapped_module = r.mapped_file.empty() ? L"(unbacked)" : r.mapped_file;
                                        ta.is_unbacked = true;
                                        ta.is_suspicious = true;
                                        ta.description = L"Thread start address is inside unbacked executable memory (remote thread injection)";
                                        report.has_unbacked_threads = true;
                                        ++report.critical_anomalies_count;
                                        report.thread_anomalies.push_back(std::move(ta));
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    CloseHandle(hThread);
                }
            } while (Thread32Next(hThreadSnap, &te));
        }

        CloseHandle(hThreadSnap);
    }

    return report;
}

} // namespace vmemscan
