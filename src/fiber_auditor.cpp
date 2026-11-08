#include "vmemscan/fiber_auditor.hpp"
#include "vmemscan/nt_defs.hpp"

#include <tlhelp32.h>
#include <winternl.h>

namespace vmemscan {

std::wstring FiberAuditor::anomaly_type_to_string(FiberAnomalyType type) {
    switch (type) {
    case FiberAnomalyType::UnbackedFiberStart:
        return L"Fiber Start Routine in Unbacked Memory (Fiber injection)";
    case FiberAnomalyType::RwxFiberStart:
        return L"Fiber Start Routine in RWX Memory (W^X breach)";
    case FiberAnomalyType::UnbackedFiberStack:
        return L"Fiber Execution Stack in Anonymous Memory Block";
    case FiberAnomalyType::UnbackedFlsCallback:
        return L"Fiber Local Storage (FLS) Callback in Unbacked Memory";
    case FiberAnomalyType::RwxFlsCallback:
        return L"Fiber Local Storage (FLS) Callback in RWX Memory";
    default:
        return L"Unknown";
    }
}

#pragma pack(push, 8)
struct InternalThreadBasicInfo {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
};
#pragma pack(pop)

FiberReport FiberAuditor::audit_process(HANDLE hProcess, uint32_t pid) {
    FiberReport report{};
    report.process_id = pid;

    if (!hProcess || pid == 0) {
        return report;
    }

    auto pfnQueryThread = NtApiLoader::get_nt_query_information_thread();
    if (!pfnQueryThread) {
        return report;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return report;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }

            ++report.threads_examined;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!hThread) {
                hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            }
            if (!hThread) {
                continue;
            }

            InternalThreadBasicInfo tbi{};
            NTSTATUS status = pfnQueryThread(
                hThread,
                ThreadBasicInformation,
                &tbi,
                sizeof(tbi),
                nullptr
            );

            if (status == 0 && tbi.TebBaseAddress != nullptr) {
                // Read NT_TIB from TEB
                // Offset 0x20 is FiberData on 64-bit architecture
                uint64_t fiber_data_addr = 0;
                SIZE_T bytes_read = 0;
                uint64_t fiber_offset = (sizeof(void*) == 8) ? 0x20 : 0x10;

                if (ReadProcessMemory(
                    hProcess,
                    reinterpret_cast<LPCVOID>(reinterpret_cast<uintptr_t>(tbi.TebBaseAddress) + fiber_offset),
                    &fiber_data_addr,
                    sizeof(fiber_data_addr),
                    &bytes_read
                ) && bytes_read == sizeof(fiber_data_addr)) {
                    // Check if fiber_data_addr is a valid user-mode pointer
                    // 0x1e00 or 0 or values < 0x10000 are OS placeholders / absent fibers
                    if (fiber_data_addr >= 0x10000 && fiber_data_addr < 0x7FFFFFFF0000ULL) {
                        ++report.fibers_detected;

                        // Query memory properties of the FiberData structure itself
                        MEMORY_BASIC_INFORMATION mbi_fiber{};
                        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(fiber_data_addr), &mbi_fiber, sizeof(mbi_fiber))) {
                            // Read initial 64 bytes of fiber structure
                            // Offset 0x10: stack_base
                            // Offset 0x18: stack_limit
                            // Offset 0x20: deallocation_stack
                            uint64_t fiber_fields[8]{};
                            if (ReadProcessMemory(
                                hProcess,
                                reinterpret_cast<LPCVOID>(fiber_data_addr),
                                fiber_fields,
                                sizeof(fiber_fields),
                                &bytes_read
                            ) && bytes_read == sizeof(fiber_fields)) {
                                uint64_t fiber_stack_base = fiber_fields[2];
                                uint64_t fiber_stack_limit = fiber_fields[3];

                                if (fiber_stack_base > fiber_stack_limit &&
                                    fiber_stack_limit >= 0x10000 &&
                                    fiber_stack_base < 0x7FFFFFFF0000ULL) {
                                    MEMORY_BASIC_INFORMATION mbi_stack{};
                                    if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(fiber_stack_limit), &mbi_stack, sizeof(mbi_stack))) {
                                        bool is_unbacked = (mbi_stack.Type == MEM_PRIVATE || mbi_stack.Type == MEM_MAPPED);
                                        bool is_exec = (mbi_stack.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                                        if (is_unbacked && is_exec) {
                                            FiberAnomaly fa{};
                                            fa.thread_id = te.th32ThreadID;
                                            fa.fiber_data_address = fiber_data_addr;
                                            fa.target_address = fiber_stack_limit;
                                            fa.anomaly_type = FiberAnomalyType::UnbackedFiberStack;
                                            fa.anomaly_description = L"Fiber stack allocated in executable unbacked memory";
                                            fa.memory_protection = mbi_stack.Protect;
                                            fa.memory_type = mbi_stack.Type;
                                            fa.memory_state = mbi_stack.State;
                                            report.anomalies.push_back(fa);
                                        }
                                    }
                                }
                            }
                        }

                        // Inspect potential fiber entry routine / target pointer within the fiber record
                        // On x64, Windows fiber context holds RIP / Callback pointers in the record
                        uint8_t fiber_raw[512]{};
                        if (ReadProcessMemory(
                            hProcess,
                            reinterpret_cast<LPCVOID>(fiber_data_addr),
                            fiber_raw,
                            sizeof(fiber_raw),
                            &bytes_read
                        ) && bytes_read >= 128) {
                            for (size_t off = 0; off + 8 <= bytes_read; off += 8) {
                                uint64_t ptr_val = *reinterpret_cast<uint64_t*>(fiber_raw + off);
                                if (ptr_val < 0x10000 || ptr_val >= 0x7FFFFFFF0000ULL) {
                                    continue;
                                }

                                MEMORY_BASIC_INFORMATION mbi_ptr{};
                                if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(ptr_val), &mbi_ptr, sizeof(mbi_ptr))) {
                                    if (mbi_ptr.State == MEM_COMMIT) {
                                        bool is_exec = (mbi_ptr.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                                        bool is_rwx = (mbi_ptr.Protect & PAGE_EXECUTE_READWRITE) != 0;
                                        bool is_unbacked = (mbi_ptr.Type == MEM_PRIVATE || mbi_ptr.Type == MEM_MAPPED);

                                        if (is_exec && is_unbacked) {
                                            FiberAnomaly fa{};
                                            fa.thread_id = te.th32ThreadID;
                                            fa.fiber_data_address = fiber_data_addr;
                                            fa.target_address = ptr_val;
                                            fa.anomaly_type = is_rwx ? FiberAnomalyType::RwxFiberStart : FiberAnomalyType::UnbackedFiberStart;
                                            fa.anomaly_description = is_rwx
                                                ? L"Fiber routine pointer targets RWX unbacked memory"
                                                : L"Fiber routine pointer targets unbacked executable memory";
                                            fa.memory_protection = mbi_ptr.Protect;
                                            fa.memory_type = mbi_ptr.Type;
                                            fa.memory_state = mbi_ptr.State;
                                            report.anomalies.push_back(fa);
                                            break; // Found primary anomalous routine
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);

    // Audit Process PEB FLS (Fiber Local Storage) callbacks
    auto pfnQueryProcess = NtApiLoader::get_nt_query_information_process();
    if (pfnQueryProcess) {
        PROCESS_BASIC_INFORMATION pbi{};
        NTSTATUS pstatus = pfnQueryProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
        if (pstatus == 0 && pbi.PebBaseAddress != nullptr) {
            // PEB FlsCallback array is at offset 0x320 on 64-bit Windows 10/11
            uint64_t fls_callback_offset = (sizeof(void*) == 8) ? 0x320 : 0x20c;
            uint64_t fls_callback_ptr = 0;
            SIZE_T read = 0;

            if (ReadProcessMemory(
                hProcess,
                reinterpret_cast<LPCVOID>(reinterpret_cast<uintptr_t>(pbi.PebBaseAddress) + fls_callback_offset),
                &fls_callback_ptr,
                sizeof(fls_callback_ptr),
                &read
            ) && read == sizeof(fls_callback_ptr) && fls_callback_ptr >= 0x10000 && fls_callback_ptr < 0x7FFFFFFF0000ULL) {
                // Read up to 64 FLS callbacks
                uint64_t callbacks[64]{};
                if (ReadProcessMemory(
                    hProcess,
                    reinterpret_cast<LPCVOID>(fls_callback_ptr),
                    callbacks,
                    sizeof(callbacks),
                    &read
                )) {
                    size_t count = read / sizeof(uint64_t);
                    for (size_t i = 0; i < count; ++i) {
                        uint64_t cb = callbacks[i];
                        if (cb < 0x10000 || cb >= 0x7FFFFFFF0000ULL) {
                            continue;
                        }
                        ++report.fls_callbacks_examined;

                        MEMORY_BASIC_INFORMATION mbi_cb{};
                        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(cb), &mbi_cb, sizeof(mbi_cb))) {
                            if (mbi_cb.State == MEM_COMMIT) {
                                bool is_exec = (mbi_cb.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                                bool is_rwx = (mbi_cb.Protect & PAGE_EXECUTE_READWRITE) != 0;
                                bool is_unbacked = (mbi_cb.Type == MEM_PRIVATE || mbi_cb.Type == MEM_MAPPED);

                                if (is_exec && is_unbacked) {
                                    FiberAnomaly fa{};
                                    fa.thread_id = 0;
                                    fa.fiber_data_address = fls_callback_ptr;
                                    fa.target_address = cb;
                                    fa.anomaly_type = is_rwx ? FiberAnomalyType::RwxFlsCallback : FiberAnomalyType::UnbackedFlsCallback;
                                    fa.anomaly_description = is_rwx
                                        ? L"FLS callback registered in RWX unbacked memory"
                                        : L"FLS callback registered in unbacked executable memory";
                                    fa.memory_protection = mbi_cb.Protect;
                                    fa.memory_type = mbi_cb.Type;
                                    fa.memory_state = mbi_cb.State;
                                    report.anomalies.push_back(fa);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return report;
}

} // namespace vmemscan
