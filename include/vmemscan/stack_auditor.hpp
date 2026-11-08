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

struct StackFrameAnomaly {
    uint32_t thread_id = 0;
    uint64_t stack_slot_address = 0;
    uint64_t return_address = 0;
    bool is_unbacked = false;
    bool is_rwx = false;
    std::wstring mapped_module;
    std::wstring anomaly_description;
};

struct StackAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t threads_inspected = 0;
    size_t total_frames_scanned = 0;
    size_t unbacked_frames_count = 0;
    std::vector<StackFrameAnomaly> anomalies;
};

class StackAuditor {
public:
    static StackAuditReport audit_process_stacks(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::vector<StackFrameAnomaly> scan_stack_buffer(
        uint32_t thread_id,
        const uint8_t* stack_data,
        size_t stack_size,
        uint64_t rsp_base,
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
