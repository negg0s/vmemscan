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

enum class UnwindAnomalyType {
    None,
    UnwindMetadataMissing,        // Stack frame RVA within module lacks RUNTIME_FUNCTION in .pdata (Stack Spoofing)
    UnbackedStackFrame,          // Stack frame points to unbacked private memory
    RwxStackFrame                // Stack frame points to PAGE_EXECUTE_READWRITE memory
};

struct UnwindFunctionEntry {
    uint32_t begin_rva = 0;
    uint32_t end_rva = 0;
};

struct UnwindAnomaly {
    uint32_t thread_id = 0;
    uint64_t frame_address = 0;
    std::wstring module_name;
    uint64_t module_base = 0;
    uint32_t rva = 0;
    UnwindAnomalyType type = UnwindAnomalyType::None;
    bool is_critical = false;
    std::wstring details;
};

struct UnwindAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t threads_inspected = 0;
    size_t frames_evaluated = 0;
    size_t anomalous_frames_count = 0;
    std::vector<UnwindAnomaly> anomalies;
};

class UnwindAuditor {
public:
    static UnwindAuditReport audit_process_unwind(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::wstring anomaly_type_to_string(UnwindAnomalyType type);

    static bool verify_rva_in_functions(
        uint32_t rva,
        const std::vector<UnwindFunctionEntry>& functions
    );

    // Pure evaluation function for unit tests and stack analysis
    static std::vector<UnwindAnomaly> evaluate_thread_frames(
        uint32_t thread_id,
        const std::vector<uint64_t>& stack_frames,
        uint64_t module_base,
        uint64_t module_size,
        const std::wstring& module_name,
        const std::vector<UnwindFunctionEntry>& module_functions,
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
