#include "vmemscan/anti_debug_auditor.hpp"
#include "vmemscan/nt_defs.hpp"

#include <tlhelp32.h>

namespace vmemscan {

AntiDebugReport AntiDebugAuditor::audit_process_anti_debug(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    bool is_64bit
) {
    AntiDebugReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || pid == 0) {
        return rep;
    }

    auto pfnQueryProc = NtApiLoader::get_nt_query_information_process();
    if (!pfnQueryProc) {
        return rep;
    }

    // 1. ProcessDebugPort (Class 7)
    DWORD_PTR debug_port = 0;
    ULONG ret_len = 0;
    if (pfnQueryProc(hProcess, static_cast<PROCESSINFOCLASS>(7), &debug_port, sizeof(debug_port), &ret_len) == 0) {
        if (debug_port != 0) {
            rep.kernel_debugger_present = true;
            AntiDebugFinding f{};
            f.category = L"Kernel Debugging";
            f.indicator_name = L"ProcessDebugPort";
            f.value = static_cast<uint64_t>(debug_port);
            f.details = L"Active kernel debug port assigned to process (Debugger attached)";
            f.is_anti_debug = false;
            rep.findings.push_back(std::move(f));
        }
    }

    // 2. ProcessDebugFlags (Class 31)
    ULONG debug_flags = 1;
    if (pfnQueryProc(hProcess, static_cast<PROCESSINFOCLASS>(31), &debug_flags, sizeof(debug_flags), &ret_len) == 0) {
        if (debug_flags == 0) {
            rep.anti_debug_flags_detected = true;
            AntiDebugFinding f{};
            f.category = L"Process Security";
            f.indicator_name = L"ProcessDebugFlags";
            f.value = 0;
            f.details = L"NoDebugInherit active: ProcessDebugFlags set to 0 (Debugger detached or suppressed)";
            f.is_anti_debug = true;
            rep.findings.push_back(std::move(f));
        }
    }

    // 3. ProcessDebugObjectHandle (Class 30)
    HANDLE debug_obj = nullptr;
    if (pfnQueryProc(hProcess, static_cast<PROCESSINFOCLASS>(30), &debug_obj, sizeof(debug_obj), &ret_len) == 0) {
        if (debug_obj != nullptr) {
            rep.kernel_debugger_present = true;
            AntiDebugFinding f{};
            f.category = L"Kernel Debugging";
            f.indicator_name = L"ProcessDebugObjectHandle";
            f.value = reinterpret_cast<uint64_t>(debug_obj);
            f.details = L"Kernel debug object handle exists for target process";
            f.is_anti_debug = false;
            rep.findings.push_back(std::move(f));
        }
    }

    // 4. Query PEB (BeingDebugged and NtGlobalFlag)
    PROCESS_BASIC_INFORMATION pbi{};
    if (pfnQueryProc(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len) == 0 && pbi.PebBaseAddress) {
        uint64_t peb_addr = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);
        SIZE_T read = 0;

        // BeingDebugged at offset 0x02
        uint8_t being_debugged = 0;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(peb_addr + 2), &being_debugged, 1, &read) && being_debugged != 0) {
            rep.peb_being_debugged = true;
            AntiDebugFinding f{};
            f.category = L"PEB Structure";
            f.indicator_name = L"BeingDebugged";
            f.value = being_debugged;
            f.details = L"PEB BeingDebugged flag set to 1 (User-mode debugger active)";
            f.is_anti_debug = false;
            rep.findings.push_back(std::move(f));
        }

        // NtGlobalFlag offset: 0xBC for 64-bit, 0x68 for 32-bit
        uint64_t nt_global_flag_offset = is_64bit ? 0xBC : 0x68;
        uint32_t nt_global_flag = 0;
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(peb_addr + nt_global_flag_offset), &nt_global_flag, sizeof(nt_global_flag), &read) && nt_global_flag != 0) {
            if (nt_global_flag & 0x70) {
                rep.anti_debug_flags_detected = true;
                AntiDebugFinding f{};
                f.category = L"PEB Structure";
                f.indicator_name = L"NtGlobalFlag";
                f.value = nt_global_flag;
                f.details = L"Heap validation flags enabled (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)";
                f.is_anti_debug = true;
                rep.findings.push_back(std::move(f));
            }
        }
    }

    // 5. Query Hardware Breakpoint Registers across threads
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
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
#if defined(_M_X64)
                    bool is_current = (te.th32ThreadID == GetCurrentThreadId());
                    DWORD suspend_res = 0;
                    if (!is_current) {
                        suspend_res = SuspendThread(hThread);
                    }
                    if (is_current || suspend_res != static_cast<DWORD>(-1)) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (GetThreadContext(hThread, &ctx)) {
                            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || ctx.Dr7 != 0) {
                                rep.hardware_breakpoints_present = true;
                                AntiDebugFinding f{};
                                f.category = L"Hardware Breakpoints";
                                f.indicator_name = L"Debug Registers (DR0-DR7)";
                                f.value = ctx.Dr7;
                                f.details = L"Thread TID " + std::to_wstring(te.th32ThreadID) +
                                            L" has active hardware breakpoint registers (VEH Hooking / Evasion)";
                                f.is_anti_debug = true;
                                rep.findings.push_back(std::move(f));
                            }
                        }
                        if (!is_current) {
                            ResumeThread(hThread);
                        }
                    }
#endif
                    CloseHandle(hThread);
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

    return rep;
}

} // namespace vmemscan
