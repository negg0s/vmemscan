#pragma once

#include "vmemscan/common.hpp"

#include <string>
#include <vector>

namespace vmemscan {

struct ProcessFilter {
    uint32_t pid{0};
    std::wstring name_pattern;
    bool only_64bit{false};
    bool only_elevated{false};
};

class ProcessSnapshot {
public:
    static std::vector<ProcessInfo> enumerate_processes(const ProcessFilter& filter = {});
    static Result<ProcessInfo> get_process_by_pid(uint32_t pid);
    static HANDLE open_process_for_inspection(uint32_t pid);
    static bool match_wildcard(const std::wstring& pattern, const std::wstring& text);
};

} // namespace vmemscan
