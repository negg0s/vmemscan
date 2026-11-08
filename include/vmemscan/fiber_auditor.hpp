#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

enum class FiberAnomalyType {
    UnbackedFiberStart,     // Fiber start routine points to unbacked private/mapped memory
    RwxFiberStart,          // Fiber start routine points to PAGE_EXECUTE_READWRITE
    UnbackedFiberStack,     // Fiber stack is allocated in unbacked memory
    UnbackedFlsCallback,    // FLS callback pointer points to unbacked memory
    RwxFlsCallback          // FLS callback pointer points to RWX memory
};

struct FiberAnomaly {
    uint32_t thread_id = 0;
    uint64_t fiber_data_address = 0;
    uint64_t target_address = 0;
    FiberAnomalyType anomaly_type = FiberAnomalyType::UnbackedFiberStart;
    std::wstring anomaly_description;
    std::wstring backing_module;
    DWORD memory_protection = 0;
    DWORD memory_type = 0;
    DWORD memory_state = 0;
};

struct FiberReport {
    uint32_t process_id = 0;
    size_t threads_examined = 0;
    size_t fibers_detected = 0;
    size_t fls_callbacks_examined = 0;
    std::vector<FiberAnomaly> anomalies;
};

class FiberAuditor {
public:
    static FiberReport audit_process(HANDLE hProcess, uint32_t pid);
    static std::wstring anomaly_type_to_string(FiberAnomalyType type);
};

} // namespace vmemscan
