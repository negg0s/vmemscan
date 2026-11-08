#include "vmemscan/thread_analyzer.hpp"
#include "vmemscan/nt_defs.hpp"

#include <tlhelp32.h>

namespace vmemscan {

std::wstring ThreadAnalyzer::anomaly_to_string(ThreadAnomalyType type) {
    switch (type) {
    case ThreadAnomalyType::None:                       return L"None";
    case ThreadAnomalyType::UnbackedStartAddress:       return L"Unbacked Start Address (CreateRemoteThread shellcode entry)";
    case ThreadAnomalyType::UnbackedInstructionPointer: return L"Instruction Pointer in Unbacked Memory (Active shellcode execution)";
    case ThreadAnomalyType::RwxExecution:               return L"Instruction Pointer in RWX Memory (W^X breach)";
    case ThreadAnomalyType::SuspiciousModule:           return L"Instruction Pointer in Anonymous Memory Block";
    default:                                            return L"Unknown";
    }
}

ThreadAuditReport ThreadAnalyzer::audit_process_threads(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    ThreadAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || pid == 0) {
        return rep;
    }

    auto find_region = [&](uint64_t addr) -> const MemoryRegion* {
        if (addr == 0) return nullptr;
        for (const auto& r : regions) {
            if (addr >= r.base_address && addr < r.base_address + r.region_size) {
                return &r;
            }
        }
        return nullptr;
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return rep;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    auto pfnQueryThread = NtApiLoader::get_nt_query_information_thread();

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }

            ++rep.total_threads;

            ThreadInfo info{};
            info.thread_id = te.th32ThreadID;

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                FALSE,
                te.th32ThreadID
            );

            if (hThread) {
                // 1. Resolve start address via NT API
                if (pfnQueryThread) {
                    PVOID start_addr = nullptr;
                    ULONG ret_len = 0;
                    NTSTATUS status = pfnQueryThread(
                        hThread,
                        ThreadQuerySetWin32StartAddress,
                        &start_addr,
                        sizeof(start_addr),
                        &ret_len
                    );

                    if (status == 0 && start_addr) {
                        info.start_address = reinterpret_cast<uint64_t>(start_addr);
                        const auto* start_reg = find_region(info.start_address);
                        if (start_reg) {
                            info.start_module = start_reg->mapped_file;
                            if (start_reg->is_unbacked_executable) {
                                info.is_start_unbacked = true;
                                info.anomalies.push_back(ThreadAnomalyType::UnbackedStartAddress);
                            }
                        }
                    }
                }

                // 2. Query thread context (RIP/EIP)
#if defined(_M_X64)
                bool is_current = (te.th32ThreadID == GetCurrentThreadId());
                DWORD suspend_res = 0;
                if (!is_current) {
                    suspend_res = SuspendThread(hThread);
                }
                if (is_current || suspend_res != static_cast<DWORD>(-1)) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(hThread, &ctx)) {
                        info.rip = ctx.Rip;
                        info.rsp = ctx.Rsp;

                        const auto* rip_reg = find_region(info.rip);
                        if (rip_reg) {
                            info.rip_module = rip_reg->mapped_file;
                            if (rip_reg->is_unbacked_executable) {
                                info.is_rip_unbacked = true;
                                info.anomalies.push_back(ThreadAnomalyType::UnbackedInstructionPointer);
                            }
                            if (rip_reg->is_rwx) {
                                info.is_rip_rwx = true;
                                info.anomalies.push_back(ThreadAnomalyType::RwxExecution);
                            }

                            // Read instructions preview at current RIP
                            uint8_t buffer[16]{0};
                            SIZE_T read = 0;
                            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(info.rip), buffer, sizeof(buffer), &read) && read > 0) {
                                info.rip_bytes_preview.assign(buffer, buffer + read);
                            }
                        }
                    }
                    if (!is_current) {
                        ResumeThread(hThread);
                    }
                }
#endif

                CloseHandle(hThread);
            }

            if (!info.anomalies.empty()) {
                ++rep.suspicious_threads_count;
            }

            rep.threads.push_back(std::move(info));

        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return rep;
}

} // namespace vmemscan
