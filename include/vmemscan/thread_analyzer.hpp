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

enum class ThreadAnomalyType {
    None,
    UnbackedStartAddress,      // Thread start address points to MEM_PRIVATE
    UnbackedInstructionPointer, // Current RIP/EIP points to MEM_PRIVATE
    RwxExecution,              // Current RIP/EIP points to PAGE_EXECUTE_READWRITE
    SuspiciousModule           // Thread points outside recognized modules
};

struct ThreadInfo {
    uint32_t thread_id = 0;
    uint64_t start_address = 0;
    uint64_t rip = 0;
    uint64_t rsp = 0;
    bool is_start_unbacked = false;
    bool is_rip_unbacked = false;
    bool is_rip_rwx = false;
    std::wstring start_module;
    std::wstring rip_module;
    std::vector<uint8_t> rip_bytes_preview;
    std::vector<ThreadAnomalyType> anomalies;
};

struct ThreadAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t total_threads = 0;
    size_t suspicious_threads_count = 0;
    std::vector<ThreadInfo> threads;
};

class ThreadAnalyzer {
public:
    static ThreadAuditReport audit_process_threads(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::wstring anomaly_to_string(ThreadAnomalyType type);
};

} // namespace vmemscan
