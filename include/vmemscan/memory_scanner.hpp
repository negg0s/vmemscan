#pragma once

#include "vmemscan/common.hpp"

#include <string>
#include <vector>

namespace vmemscan {

struct MemoryFilter {
    bool only_executable{false};
    bool only_unbacked{false};
    bool only_rwx{false};
    bool only_private{false};
    uint64_t min_size{0};
};

class MemoryScanner {
public:
    static Result<std::vector<MemoryRegion>> scan_process_memory(
        HANDLE hProcess,
        const MemoryFilter& filter = {}
    );

    static ProcessMemorySummary compute_summary(
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::wstring protect_to_string(uint32_t protect);
    static std::wstring state_to_string(uint32_t state);
    static std::wstring type_to_string(uint32_t type);
};

} // namespace vmemscan
