#include "vmemscan/sleep_mask_detector.hpp"
#include "vmemscan/memory_scanner.hpp"
#include "vmemscan/nt_defs.hpp"

#include <algorithm>
#include <tlhelp32.h>

namespace vmemscan {

std::vector<SleepMaskAnomaly> SleepMaskDetector::scan_stack_for_masked_pages(
    uint32_t thread_id,
    const uint64_t* stack_slots,
    size_t num_slots,
    const std::vector<MemoryRegion>& regions
) {
    std::vector<SleepMaskAnomaly> anomalies;
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
        uint64_t ret_addr = stack_slots[i];
        if (ret_addr == 0) continue;

        const auto* reg = find_region(ret_addr);
        if (!reg) continue;

        // Check if return address resides in a demoted memory page (allocated as executable
        // but currently non-executable, e.g. PAGE_READWRITE or PAGE_NOACCESS to hide implant code)
        const bool was_allocated_executable = (reg->alloc_protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (reg->type == MEM_PRIVATE && !reg->is_executable && reg->state == MEM_COMMIT && was_allocated_executable) {
            // Deduplicate per thread and region base
            bool already_reported = false;
            for (const auto& existing : anomalies) {
                if (existing.thread_id == thread_id && existing.target_region_base == reg->base_address) {
                    already_reported = true;
                    break;
                }
            }
            if (already_reported) continue;

            SleepMaskAnomaly a{};
            a.thread_id = thread_id;
            a.wait_return_address = ret_addr;
            a.target_region_base = reg->base_address;
            a.target_region_size = reg->region_size;
            a.current_protection = reg->protect;
            a.protection_string = MemoryScanner::protect_to_string(reg->protect);
            a.anomaly_description = L"Sleep Mask Evasion: Return address resides in private non-executable page (allocated executable, demoted to " +
                                  a.protection_string + L" while sleeping)";
            anomalies.push_back(std::move(a));
        } else if (reg->type == MEM_PRIVATE && reg->is_rwx && reg->state == MEM_COMMIT) {
            // Unbacked RWX page caller
            bool already_reported = false;
            for (const auto& existing : anomalies) {
                if (existing.thread_id == thread_id && existing.target_region_base == reg->base_address) {
                    already_reported = true;
                    break;
                }
            }
            if (already_reported) continue;

            SleepMaskAnomaly a{};
            a.thread_id = thread_id;
            a.wait_return_address = ret_addr;
            a.target_region_base = reg->base_address;
            a.target_region_size = reg->region_size;
            a.current_protection = reg->protect;
            a.protection_string = MemoryScanner::protect_to_string(reg->protect);
            a.anomaly_description = L"Sleeping thread caller resides in unbacked RWX private memory page";
            anomalies.push_back(std::move(a));
        }
    }

    return anomalies;
}

SleepMaskReport SleepMaskDetector::audit_process_sleep_mask(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    SleepMaskReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || pid == 0) {
        return rep;
    }

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
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE,
                te.th32ThreadID
            );

            if (hThread) {
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
                            ++rep.sleeping_threads_scanned;
                            const size_t sample_slots = 64;
                            std::vector<uint64_t> stack_slots(sample_slots);
                            SIZE_T read = 0;

                            if (ReadProcessMemory(
                                hProcess,
                                reinterpret_cast<LPCVOID>(sp),
                                stack_slots.data(),
                                sample_slots * sizeof(uint64_t),
                                &read
                            ) && read >= sizeof(uint64_t)) {
                                size_t num_read = read / sizeof(uint64_t);
                                auto found = scan_stack_for_masked_pages(
                                    te.th32ThreadID,
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
#else
                (void)regions;
#endif
                CloseHandle(hThread);
            }

        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    rep.masked_regions_count = rep.anomalies.size();
    return rep;
}

} // namespace vmemscan
