#include "vmemscan/hook_detector.hpp"

#include <psapi.h>
#include <tlhelp32.h>
#include <cstring>

namespace vmemscan {

bool HookDetector::is_hook_instruction(
    const uint8_t* code,
    size_t size,
    std::wstring& hook_type,
    uint64_t func_addr,
    uint64_t& target_addr
) {
    if (code == nullptr || size < 5) {
        return false;
    }

    target_addr = 0;

    // Pattern 1: Relative 32-bit JMP (E9 xx xx xx xx)
    if (code[0] == 0xE9 && size >= 5) {
        hook_type = L"JMP (Rel32)";
        int32_t rel_offset = 0;
        std::memcpy(&rel_offset, code + 1, sizeof(int32_t));
        target_addr = func_addr + 5 + static_cast<int64_t>(rel_offset);
        return true;
    }

    // Pattern 2: Relative 32-bit CALL (E8 xx xx xx xx)
    if (code[0] == 0xE8 && size >= 5) {
        hook_type = L"CALL (Rel32)";
        int32_t rel_offset = 0;
        std::memcpy(&rel_offset, code + 1, sizeof(int32_t));
        target_addr = func_addr + 5 + static_cast<int64_t>(rel_offset);
        return true;
    }

    // Pattern 3: Indirect 64-bit JMP (FF 25 00 00 00 00 [8 bytes target])
    if (size >= 14 && code[0] == 0xFF && code[1] == 0x25 &&
        code[2] == 0x00 && code[3] == 0x00 && code[4] == 0x00 && code[5] == 0x00) {
        hook_type = L"JMP (QWORD Indirect)";
        std::memcpy(&target_addr, code + 6, sizeof(uint64_t));
        return true;
    }

    // Pattern 4: MOV R10, 64-bit; JMP R10 (49 BA [8 bytes target] 41 FF E2)
    if (size >= 13 && code[0] == 0x49 && code[1] == 0xBA &&
        code[10] == 0x41 && code[11] == 0xFF && code[12] == 0xE2) {
        hook_type = L"MOV R10 + JMP R10";
        std::memcpy(&target_addr, code + 2, sizeof(uint64_t));
        return true;
    }

    // Pattern 5: MOV RAX, 64-bit; JMP RAX (48 B8 [8 bytes target] FF E0)
    if (size >= 12 && code[0] == 0x48 && code[1] == 0xB8 &&
        code[10] == 0xFF && code[11] == 0xE0) {
        hook_type = L"MOV RAX + JMP RAX";
        std::memcpy(&target_addr, code + 2, sizeof(uint64_t));
        return true;
    }

    // Pattern 6: PUSH 64-bit address; RET (68 xx xx xx xx C3 / 48 B8 ... 50 C3)
    if (size >= 12 && code[0] == 0x48 && code[1] == 0xB8 &&
        code[10] == 0x50 && code[11] == 0xC3) {
        hook_type = L"PUSH + RET (64-bit)";
        std::memcpy(&target_addr, code + 2, sizeof(uint64_t));
        return true;
    }

    return false;
}

HookReport HookDetector::audit_process_hooks(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name
) {
    HookReport report{};
    report.pid = pid;
    report.process_name = process_name;

    if (!hProcess) {
        return report;
    }

    const std::vector<std::string> critical_apis = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtMapViewOfSection",
        "NtQueueApcThread",
        "NtResumeThread",
        "NtSuspendThread",
        "NtSetContextThread",
        "NtGetContextThread"
    };

    HMODULE hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hLocalNtdll) {
        return report;
    }

    // Determine ntdll base in target process
    // In Windows (ASLR), ntdll base address is uniform across processes within the same boot session
    const uint64_t remote_ntdll_base = reinterpret_cast<uint64_t>(hLocalNtdll);

    for (const auto& api_name : critical_apis) {
        FARPROC pLocalFunc = GetProcAddress(hLocalNtdll, api_name.c_str());
        if (!pLocalFunc) continue;

        ++report.inspected_functions_count;

        const uint64_t func_offset = reinterpret_cast<uint64_t>(pLocalFunc) - reinterpret_cast<uint64_t>(hLocalNtdll);
        const uint64_t remote_func_addr = remote_ntdll_base + func_offset;

        uint8_t memory_bytes[16]{0};
        SIZE_T bytes_read = 0;
        const BOOL ok = ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(remote_func_addr),
            memory_bytes,
            sizeof(memory_bytes),
            &bytes_read
        );

        if (!ok || bytes_read < 8) continue;

        std::wstring hook_type;
        uint64_t target_addr = 0;
        if (is_hook_instruction(memory_bytes, bytes_read, hook_type, remote_func_addr, target_addr)) {
            InlineHookInfo hook{};
            hook.module_name = L"ntdll.dll";
            hook.function_name = api_name;
            hook.function_address = remote_func_addr;
            hook.hook_target_address = target_addr;
            hook.hook_type = hook_type;
            hook.memory_bytes.assign(memory_bytes, memory_bytes + bytes_read);

            // Fetch clean bytes from local process (if local is clean)
            hook.original_bytes.assign(
                reinterpret_cast<const uint8_t*>(pLocalFunc),
                reinterpret_cast<const uint8_t*>(pLocalFunc) + bytes_read
            );

            // Check if target is inside known module
            HMODULE hMods[1024]{0};
            DWORD cbNeeded = 0;
            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                const DWORD count = cbNeeded / sizeof(HMODULE);
                for (DWORD i = 0; i < count; ++i) {
                    MODULEINFO mi{};
                    if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                        const uint64_t m_base = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
                        if (target_addr >= m_base && target_addr < m_base + mi.SizeOfImage) {
                            wchar_t mod_name[MAX_PATH]{0};
                            if (GetModuleBaseNameW(hProcess, hMods[i], mod_name, MAX_PATH)) {
                                hook.target_module = mod_name;
                            }
                            break;
                        }
                    }
                }
            }

            if (hook.target_module.empty()) {
                hook.target_module = L"(unbacked memory / shellcode)";
            }

            report.hooks.push_back(std::move(hook));
            ++report.detected_hooks_count;
        }
    }

    return report;
}

} // namespace vmemscan
