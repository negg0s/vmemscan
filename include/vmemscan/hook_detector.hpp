#pragma once

#include "vmemscan/common.hpp"

#include <string>
#include <vector>

namespace vmemscan {

struct InlineHookInfo {
    std::wstring module_name;
    std::string function_name;
    uint64_t function_address{0};
    uint64_t hook_target_address{0};
    std::wstring hook_type;
    std::wstring target_module;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> memory_bytes;
};

struct HookReport {
    uint32_t pid{0};
    std::wstring process_name;
    size_t inspected_functions_count{0};
    size_t detected_hooks_count{0};
    std::vector<InlineHookInfo> hooks;
};

class HookDetector {
public:
    static HookReport audit_process_hooks(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name
    );

    static bool is_hook_instruction(
        const uint8_t* code,
        size_t size,
        std::wstring& hook_type,
        uint64_t func_addr,
        uint64_t& target_addr
    );
};

} // namespace vmemscan
