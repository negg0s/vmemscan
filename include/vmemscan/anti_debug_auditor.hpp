#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "vmemscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

struct AntiDebugFinding {
    std::wstring category;
    std::wstring indicator_name;
    uint64_t value = 0;
    std::wstring details;
    bool is_anti_debug = false;
};

struct AntiDebugReport {
    uint32_t pid = 0;
    std::wstring process_name;
    bool kernel_debugger_present = false;
    bool peb_being_debugged = false;
    bool hardware_breakpoints_present = false;
    bool anti_debug_flags_detected = false;
    std::vector<AntiDebugFinding> findings;
};

class AntiDebugAuditor {
public:
    static AntiDebugReport audit_process_anti_debug(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        bool is_64bit = true
    );
};

} // namespace vmemscan
