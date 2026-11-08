#include "vmemscan/stack_auditor.hpp"

#include <algorithm>
#include <tlhelp32.h>

namespace vmemscan {

std::vector<StackFrameAnomaly> StackAuditor::scan_stack_buffer(
    uint32_t thread_id,
    const uint8_t* stack_data,
    size_t stack_size,
    uint64_t rsp_base,
    const std::vector<MemoryRegion>& regions
) {
    std::vector<StackFrameAnomaly> anomalies;
    if (!stack_data || stack_size < sizeof(uint64_t)) {
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

    const size_t num_slots = stack_size / sizeof(uint64_t);
    const auto* slots = reinterpret_cast<const uint64_t*>(stack_data);

    for (size_t i = 0; i < num_slots; ++i) {
        uint64_t ptr_val = slots[i];
        if (ptr_val == 0) continue;

        const auto* reg = find_region(ptr_val);
        if (!reg || !reg->is_executable) {
            continue;
        }

        if (reg->is_unbacked_executable || reg->is_rwx) {
            StackFrameAnomaly a{};
            a.thread_id = thread_id;
            a.stack_slot_address = rsp_base + (i * sizeof(uint64_t));
            a.return_address = ptr_val;
            a.is_unbacked = reg->is_unbacked_executable;
            a.is_rwx = reg->is_rwx;
            a.mapped_module = reg->mapped_file;

            if (reg->is_unbacked_executable && reg->is_rwx) {
                a.anomaly_description = L"Return address points to unbacked RWX memory page (Shellcode / Stager)";
            } else if (reg->is_unbacked_executable) {
                a.anomaly_description = L"Return address points to unbacked private memory (Reflective DLL / Implant)";
            } else {
                a.anomaly_description = L"Return address points to writable executable memory (W^X violation)";
            }

            anomalies.push_back(std::move(a));
        }
    }

    return anomalies;
}

StackAuditReport StackAuditor::audit_process_stacks(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    StackAuditReport rep{};
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

            ++rep.threads_inspected;

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE,
                te.th32ThreadID
            );

            if (hThread) {
#if defined(_M_X64)
                DWORD suspend_res = SuspendThread(hThread);
                if (suspend_res != static_cast<DWORD>(-1)) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(hThread, &ctx) && ctx.Rsp != 0) {
                        // Sample up to 4096 bytes (512 stack pointer slots) from RSP
                        const size_t sample_size = 4096;
                        std::vector<uint8_t> stack_bytes(sample_size);
                        SIZE_T read = 0;

                        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(ctx.Rsp), stack_bytes.data(), sample_size, &read) && read >= sizeof(uint64_t)) {
                            rep.total_frames_scanned += (read / sizeof(uint64_t));

                            auto found = scan_stack_buffer(
                                te.th32ThreadID,
                                stack_bytes.data(),
                                read,
                                ctx.Rsp,
                                regions
                            );

                            for (auto& a : found) {
                                rep.anomalies.push_back(std::move(a));
                            }
                        }
                    }
                    ResumeThread(hThread);
                }
#endif
                CloseHandle(hThread);
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);

    rep.unbacked_frames_count = rep.anomalies.size();
    return rep;
}

} // namespace vmemscan
