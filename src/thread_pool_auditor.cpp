#include "vmemscan/thread_pool_auditor.hpp"
#include "vmemscan/memory_scanner.hpp"
#include "vmemscan/nt_defs.hpp"

#include <algorithm>
#include <tlhelp32.h>

namespace vmemscan {

std::vector<ThreadPoolAnomaly> ThreadPoolAuditor::scan_worker_stack(
    uint32_t thread_id,
    uint64_t worker_start,
    const uint64_t* stack_slots,
    size_t num_slots,
    const std::vector<MemoryRegion>& regions
) {
    std::vector<ThreadPoolAnomaly> anomalies;
    if (!stack_slots || num_slots == 0) {
        return anomalies;
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

    for (size_t i = 0; i < num_slots; ++i) {
        uint64_t ptr_val = stack_slots[i];
        if (ptr_val == 0) continue;

        const auto* reg = find_region(ptr_val);
        if (!reg) continue;

        // In legitimate thread pool execution, all callbacks and return addresses
        // reside in disk-backed DLLs (MEM_IMAGE).
        // If a callback/return address points into unbacked private memory or an RWX page:
        if (reg->is_unbacked_executable || reg->is_rwx) {
            // Deduplicate per thread and callback address
            bool already_found = false;
            for (const auto& existing : anomalies) {
                if (existing.thread_id == thread_id && existing.callback_address == ptr_val) {
                    already_found = true;
                    break;
                }
            }
            if (already_found) continue;

            ThreadPoolAnomaly a{};
            a.thread_id = thread_id;
            a.worker_start_address = worker_start;
            a.callback_address = ptr_val;
            a.callback_module = reg->mapped_file;
            a.memory_protection = reg->protect;
            a.protection_string = MemoryScanner::protect_to_string(reg->protect);
            a.is_unbacked = reg->is_unbacked_executable;
            a.is_rwx = reg->is_rwx;

            if (reg->is_unbacked_executable && reg->is_rwx) {
                a.anomaly_description = L"Thread pool worker executing in unbacked RWX memory page (PoolParty / Shellcode Worker Hijack)";
            } else if (reg->is_unbacked_executable) {
                a.anomaly_description = L"Thread pool worker callback dispatched to unbacked private memory (PoolParty TP_WORK / TP_TIMER injection)";
            } else {
                a.anomaly_description = L"Thread pool worker callback dispatched to writable executable memory (W^X violation in worker thread)";
            }

            anomalies.push_back(std::move(a));
        }
    }

    return anomalies;
}

ThreadPoolAuditReport ThreadPoolAuditor::audit_process_thread_pool(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    ThreadPoolAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || pid == 0) {
        return rep;
    }

    auto pfnQueryThread = NtApiLoader::get_nt_query_information_thread();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return rep;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                FALSE,
                te.th32ThreadID
            );

            if (hThread) {
                uint64_t start_addr = 0;
                if (pfnQueryThread) {
                    PVOID start_pvoid = nullptr;
                    ULONG ret_len = 0;
                    if (pfnQueryThread(
                        hThread,
                        ThreadQuerySetWin32StartAddress,
                        &start_pvoid,
                        sizeof(start_pvoid),
                        &ret_len
                    ) == 0 && start_pvoid) {
                        start_addr = reinterpret_cast<uint64_t>(start_pvoid);
                    }
                }

                // Check if thread is a thread pool worker (start address in ntdll)
                bool is_pool_worker = false;
                for (const auto& r : regions) {
                    if (start_addr >= r.base_address && start_addr < r.base_address + r.region_size) {
                        if (r.mapped_file.find(L"ntdll.dll") != std::wstring::npos) {
                            is_pool_worker = true;
                        }
                        break;
                    }
                }

                if (is_pool_worker) {
                    ++rep.pool_workers_scanned;

#if defined(_M_X64) || defined(_M_ARM64)
                    bool is_current = (te.th32ThreadID == GetCurrentThreadId());
                    DWORD suspend_res = 0;
                    if (!is_current) {
                        suspend_res = SuspendThread(hThread);
                    }

                    if (is_current || suspend_res != static_cast<DWORD>(-1)) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_CONTROL;
                        if (GetThreadContext(hThread, &ctx)) {
#if defined(_M_X64)
                            uint64_t sp = ctx.Rsp;
#elif defined(_M_ARM64)
                            uint64_t sp = ctx.Sp;
#endif
                            if (sp != 0) {
                                const size_t sample_slots = 64;
                                std::vector<uint64_t> stack_slots(sample_slots);
                                SIZE_T bytes_read = 0;

                                if (ReadProcessMemory(
                                    hProcess,
                                    reinterpret_cast<LPCVOID>(sp),
                                    stack_slots.data(),
                                    sample_slots * sizeof(uint64_t),
                                    &bytes_read
                                ) && bytes_read >= sizeof(uint64_t)) {
                                    size_t num_read = bytes_read / sizeof(uint64_t);
                                    auto found = scan_worker_stack(
                                        te.th32ThreadID,
                                        start_addr,
                                        stack_slots.data(),
                                        num_read,
                                        regions
                                    );

                                    for (auto& a : found) {
                                        rep.anomalies.push_back(std::move(a));
                                    }
                                }
                            }
                        }

                        if (!is_current) {
                            ResumeThread(hThread);
                        }
                    }
#endif
                }

                CloseHandle(hThread);
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    rep.pool_anomalies_count = rep.anomalies.size();
    return rep;
}

} // namespace vmemscan
