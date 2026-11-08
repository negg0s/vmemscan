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

struct MitigationEntry {
    std::wstring policy_name;
    std::wstring status_text;
    bool is_enforced = false;
    bool is_security_relevant = false;
    std::wstring description;
};

struct ProcessMitigationsReport {
    uint32_t pid = 0;
    std::wstring process_name;
    bool dep_enabled = false;
    bool aslr_bottom_up = false;
    bool aslr_high_entropy = false;
    bool cfg_enabled = false;
    bool acg_prohibit_dynamic_code = false;
    bool msft_signed_only = false;
    bool no_remote_images = false;
    bool no_child_processes = false;
    bool strict_handle_checks = false;
    std::vector<MitigationEntry> policies;
};

class MitigationsAuditor {
public:
    static ProcessMitigationsReport audit_process_mitigations(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name
    );
};

} // namespace vmemscan
