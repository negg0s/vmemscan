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

struct GhostingAnomaly {
    std::wstring anomaly_type;
    std::wstring disk_path;
    std::wstring details;
    bool is_critical = false;
};

struct GhostingReport {
    uint32_t pid = 0;
    std::wstring process_name;
    std::wstring disk_path;
    bool is_ghosted = false;
    bool is_herpaderped = false;
    std::vector<GhostingAnomaly> anomalies;
};

class GhostingDetector {
public:
    static GhostingReport audit_process_ghosting(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::wstring& image_path,
        uint64_t image_base,
        bool is_64bit
    );
};

} // namespace vmemscan
