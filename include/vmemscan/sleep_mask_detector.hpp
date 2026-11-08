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

struct SleepMaskAnomaly {
    uint32_t thread_id = 0;
    uint64_t wait_return_address = 0;
    uint64_t target_region_base = 0;
    uint64_t target_region_size = 0;
    uint32_t current_protection = 0;
    std::wstring protection_string;
    std::wstring anomaly_description;
};

struct SleepMaskReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t sleeping_threads_scanned = 0;
    size_t masked_regions_count = 0;
    std::vector<SleepMaskAnomaly> anomalies;
};

class SleepMaskDetector {
public:
    static SleepMaskReport audit_process_sleep_mask(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::vector<SleepMaskAnomaly> scan_stack_for_masked_pages(
        uint32_t thread_id,
        const uint64_t* stack_slots,
        size_t num_slots,
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
