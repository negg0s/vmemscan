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

struct VehAnomaly {
    uint64_t target_address = 0;
    std::wstring anomaly_type;
    std::wstring mapped_module;
    uint32_t memory_protection = 0;
    std::wstring protection_string;
    bool is_unbacked = false;
    bool is_rwx = false;
    bool is_guard_page_trap = false;
    std::wstring details;
};

struct VehAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t regions_evaluated = 0;
    size_t guard_page_traps_count = 0;
    size_t anomalous_handlers_count = 0;
    std::vector<VehAnomaly> anomalies;
};

class VehAuditor {
public:
    static VehAuditReport audit_process_veh(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::vector<VehAnomaly> scan_regions_for_guard_traps(
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
