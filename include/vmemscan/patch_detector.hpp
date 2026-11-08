#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

enum class PatchType {
    None,
    EarlyReturn,           // RET (0xC3)
    ZeroReturn,            // XOR EAX, EAX; RET
    InvalidArgReturn,      // MOV EAX, 0x80070057; RET (AMSI fail bypass)
    CustomReturn,          // MOV EAX, <val>; RET
    UnconditionalJump,     // JMP rel32 or JMP indirect
    Breakpoint,            // INT 3 (0xCC)
    NopSled,               // Repeated NOPs (0x90)
    ModifiedPrologue       // Generic byte mismatch with standard stub
};

struct SecurityPatchAnomaly {
    std::wstring module_name;
    std::string function_name;
    uint64_t virtual_address = 0;
    PatchType patch_type = PatchType::None;
    std::wstring patch_description;
    std::vector<uint8_t> prologue_bytes;
    bool is_critical = false;
};

struct PatchReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t inspected_targets_count = 0;
    std::vector<SecurityPatchAnomaly> anomalies;
};

class PatchDetector {
public:
    static PatchReport audit_process_patches(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name
    );

    static PatchType classify_prologue(const uint8_t* bytes, size_t length, std::wstring& description);
    static std::wstring patch_type_to_string(PatchType pt);

private:
    static uint64_t resolve_remote_export(
        HANDLE hProcess,
        const std::wstring& module_name,
        const std::string& function_name
    );
};

} // namespace vmemscan
