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

struct IatHookFinding {
    std::wstring imported_module;
    std::string function_name;
    uint64_t iat_entry_address = 0;
    uint64_t actual_function_pointer = 0;
    bool points_to_unbacked = false;
    bool points_to_rwx = false;
    std::wstring actual_mapped_module;
    std::wstring hook_description;
};

struct IatHookReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t total_imports_checked = 0;
    size_t hooked_imports_count = 0;
    std::vector<IatHookFinding> findings;
};

class IatHookDetector {
public:
    static IatHookReport audit_process_iat(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        bool is_64bit,
        const std::vector<MemoryRegion>& regions,
        uint64_t image_base = 0
    );
};

} // namespace vmemscan
