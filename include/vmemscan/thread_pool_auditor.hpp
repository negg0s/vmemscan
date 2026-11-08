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

struct ThreadPoolAnomaly {
    uint32_t thread_id = 0;
    uint64_t worker_start_address = 0;
    uint64_t callback_address = 0;
    std::wstring callback_module;
    uint32_t memory_protection = 0;
    std::wstring protection_string;
    bool is_unbacked = false;
    bool is_rwx = false;
    std::wstring anomaly_description;
};

struct ThreadPoolAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t pool_workers_scanned = 0;
    size_t pool_anomalies_count = 0;
    std::vector<ThreadPoolAnomaly> anomalies;
};

class ThreadPoolAuditor {
public:
    static ThreadPoolAuditReport audit_process_thread_pool(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::vector<ThreadPoolAnomaly> scan_worker_stack(
        uint32_t thread_id,
        uint64_t worker_start,
        const uint64_t* stack_slots,
        size_t num_slots,
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
