#include "vmemscan/patch_detector.hpp"

#include <tlhelp32.h>
#include <iomanip>
#include <sstream>

namespace vmemscan {

std::wstring PatchDetector::patch_type_to_string(PatchType pt) {
    switch (pt) {
    case PatchType::None:               return L"None";
    case PatchType::EarlyReturn:        return L"Early RET (0xC3)";
    case PatchType::ZeroReturn:         return L"XOR EAX, EAX; RET (Success stub)";
    case PatchType::InvalidArgReturn:   return L"MOV EAX, 0x80070057; RET (E_INVALIDARG bypass)";
    case PatchType::CustomReturn:       return L"MOV EAX, imm32; RET";
    case PatchType::UnconditionalJump:  return L"JMP (Trampoline / Redirection)";
    case PatchType::Breakpoint:         return L"INT 3 (Breakpoint 0xCC)";
    case PatchType::NopSled:            return L"NOP Sled (0x90)";
    case PatchType::ModifiedPrologue:   return L"Modified Function Entry";
    case PatchType::DebuggerSuppression:return L"Debugger Suppression (Anti-Analysis Patch)";
    default:                            return L"Unknown";
    }
}

PatchType PatchDetector::classify_prologue(const uint8_t* bytes, size_t length, std::wstring& description) {
    if (!bytes || length < 3) {
        description = L"Insufficient bytes to analyze";
        return PatchType::None;
    }

    // 1. Direct RET
    if (bytes[0] == 0xC3) {
        description = L"Function starts immediately with RET (0xC3), silencing telemetry";
        return PatchType::EarlyReturn;
    }

    // 2. Breakpoint INT 3
    if (bytes[0] == 0xCC) {
        description = L"Function starts with software breakpoint INT 3 (0xCC)";
        return PatchType::Breakpoint;
    }

    // 3. XOR EAX, EAX; RET (31 C0 C3 or 33 C0 C3)
    if ((bytes[0] == 0x31 || bytes[0] == 0x33) && bytes[1] == 0xC0 && bytes[2] == 0xC3) {
        description = L"Patched with XOR EAX, EAX; RET (returns 0/success without executing)";
        return PatchType::ZeroReturn;
    }

    // 4. XOR RAX, RAX; RET (48 31 C0 C3 or 48 33 C0 C3)
    if (length >= 4 && bytes[0] == 0x48 && (bytes[1] == 0x31 || bytes[1] == 0x33) && bytes[2] == 0xC0 && bytes[3] == 0xC3) {
        description = L"Patched with XOR RAX, RAX; RET (returns 0/success without executing)";
        return PatchType::ZeroReturn;
    }

    // 5. MOV EAX, 0x80070057; RET (B8 57 00 07 80 C3) - Classic AMSI bypass returning E_INVALIDARG
    if (length >= 6 && bytes[0] == 0xB8 && bytes[1] == 0x57 && bytes[2] == 0x00 && bytes[3] == 0x07 && bytes[4] == 0x80 && bytes[5] == 0xC3) {
        description = L"Patched with MOV EAX, 0x80070057; RET (AMSI E_INVALIDARG bypass)";
        return PatchType::InvalidArgReturn;
    }

    // 6. Generic MOV EAX, imm32; RET (B8 xx xx xx xx C3)
    if (length >= 6 && bytes[0] == 0xB8 && bytes[5] == 0xC3) {
        description = L"Patched with MOV EAX, imm32; RET (custom return code bypass)";
        return PatchType::CustomReturn;
    }

    // 7. Unconditional JMP (E9 xx xx xx xx or FF 25)
    if (bytes[0] == 0xE9) {
        description = L"Function entry hijacked with relative JMP (0xE9)";
        return PatchType::UnconditionalJump;
    }
    if (length >= 2 && bytes[0] == 0xFF && bytes[1] == 0x25) {
        description = L"Function entry hijacked with indirect JMP (0xFF 0x25)";
        return PatchType::UnconditionalJump;
    }

    // 8. NOP Sled at start (90 90 90)
    if (bytes[0] == 0x90 && bytes[1] == 0x90 && bytes[2] == 0x90) {
        description = L"Function starts with consecutive NOP instructions";
        return PatchType::NopSled;
    }

    return PatchType::None;
}

static uint64_t get_remote_module_base(uint32_t pid, const std::wstring& target_module) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    uint64_t base = 0;
    if (Module32FirstW(hSnap, &me)) {
        do {
            if (_wcsicmp(me.szModule, target_module.c_str()) == 0) {
                base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    return base;
}

uint64_t PatchDetector::resolve_remote_export(
    HANDLE hProcess,
    const std::wstring& module_name,
    const std::string& function_name
) {
    // Determine module base
    uint64_t mod_base = 0;
    if (_wcsicmp(module_name.c_str(), L"ntdll.dll") == 0) {
        HMODULE hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
        mod_base = reinterpret_cast<uint64_t>(hLocalNtdll);
    } else {
        // Find in remote process
        uint32_t pid = GetProcessId(hProcess);
        if (pid != 0) {
            mod_base = get_remote_module_base(pid, module_name);
        }
        if (mod_base == 0) {
            // Fallback: check if loaded in local process
            HMODULE hLocal = GetModuleHandleW(module_name.c_str());
            if (hLocal) {
                mod_base = reinterpret_cast<uint64_t>(hLocal);
            }
        }
    }

    if (mod_base == 0) {
        return 0;
    }

    // Read DOS header from remote process
    IMAGE_DOS_HEADER dos{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(mod_base), &dos, sizeof(dos), &read) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    // Read NT headers
    IMAGE_NT_HEADERS64 nth{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(mod_base + dos.e_lfanew), &nth, sizeof(nth), &read) ||
        nth.Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    const auto& export_data_dir = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_data_dir.VirtualAddress == 0 || export_data_dir.Size == 0) {
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exp_dir{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(mod_base + export_data_dir.VirtualAddress), &exp_dir, sizeof(exp_dir), &read)) {
        return 0;
    }

    std::vector<DWORD> functions(exp_dir.NumberOfFunctions);
    std::vector<DWORD> names(exp_dir.NumberOfNames);
    std::vector<WORD> ordinals(exp_dir.NumberOfNames);

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(mod_base + exp_dir.AddressOfFunctions), functions.data(), functions.size() * sizeof(DWORD), &read) ||
        !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(mod_base + exp_dir.AddressOfNames), names.data(), names.size() * sizeof(DWORD), &read) ||
        !ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(mod_base + exp_dir.AddressOfNameOrdinals), ordinals.data(), ordinals.size() * sizeof(WORD), &read)) {
        return 0;
    }

    for (DWORD i = 0; i < exp_dir.NumberOfNames; ++i) {
        char name_buf[128]{0};
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(mod_base + names[i]), name_buf, sizeof(name_buf) - 1, &read)) {
            if (function_name == name_buf) {
                WORD ordinal = ordinals[i];
                if (ordinal < exp_dir.NumberOfFunctions) {
                    DWORD rva = functions[ordinal];
                    return mod_base + rva;
                }
            }
        }
    }

    return 0;
}

PatchReport PatchDetector::audit_process_patches(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name
) {
    PatchReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess) {
        return rep;
    }

    struct SecurityTarget {
        std::wstring module_name;
        std::string function_name;
    };

    const std::vector<SecurityTarget> targets = {
        // Event Tracing for Windows (ETW) bypass targets
        { L"ntdll.dll", "EtwEventWrite" },
        { L"ntdll.dll", "EtwEventWriteFull" },
        { L"ntdll.dll", "NtTraceEvent" },
        // Antimalware Scan Interface (AMSI) bypass targets
        { L"amsi.dll", "AmsiScanBuffer" },
        { L"amsi.dll", "AmsiScanString" },
        { L"amsi.dll", "AmsiOpenSession" },
        // Windows Defender / Endpoint telemetry
        { L"ntdll.dll", "EtwEventRegister" },
        { L"ntdll.dll", "EtwEventEnabled" },
        // Debugger Attachment and Breakin suppression
        { L"ntdll.dll", "DbgBreakPoint" },
        { L"ntdll.dll", "DbgUiRemoteBreakin" }
    };

    for (const auto& t : targets) {
        uint64_t addr = resolve_remote_export(hProcess, t.module_name, t.function_name);
        if (addr == 0) {
            continue; // Target library not loaded in remote process
        }

        ++rep.inspected_targets_count;

        uint8_t buffer[16]{0};
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), buffer, sizeof(buffer), &read) || read < 4) {
            continue;
        }

        std::wstring desc;
        PatchType pt = PatchType::None;

        if (t.function_name == "DbgBreakPoint") {
            // Normal DbgBreakPoint begins with INT 3 (0xCC)
            if (buffer[0] != 0xCC) {
                pt = PatchType::DebuggerSuppression;
                desc = L"DbgBreakPoint patched to suppress debugger attachment";
            }
        } else if (t.function_name == "DbgUiRemoteBreakin") {
            pt = classify_prologue(buffer, read, desc);
            if (pt != PatchType::None) {
                desc = L"DbgUiRemoteBreakin patched to abort debugger connection";
            }
        } else {
            pt = classify_prologue(buffer, read, desc);
        }

        if (pt != PatchType::None) {
            SecurityPatchAnomaly anomaly{};
            anomaly.module_name = t.module_name;
            anomaly.function_name = t.function_name;
            anomaly.virtual_address = addr;
            anomaly.patch_type = pt;
            anomaly.patch_description = desc;
            anomaly.prologue_bytes.assign(buffer, buffer + read);
            anomaly.is_critical = (pt == PatchType::EarlyReturn ||
                                   pt == PatchType::ZeroReturn ||
                                   pt == PatchType::InvalidArgReturn ||
                                   pt == PatchType::UnconditionalJump ||
                                   pt == PatchType::DebuggerSuppression);
            rep.anomalies.push_back(std::move(anomaly));
        }
    }

    return rep;
}

} // namespace vmemscan
