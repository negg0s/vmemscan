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

enum class TlsAnomalyType {
    None,
    UnbackedCallback,      // TLS callback points to unbacked private memory
    ForeignModuleCallback, // TLS callback points to another module
    RwxCallback            // TLS callback points to PAGE_EXECUTE_READWRITE memory
};

struct TlsAnomaly {
    uint64_t module_base = 0;
    std::wstring module_name;
    uint64_t callback_address = 0;
    uint32_t memory_protection = 0;
    std::wstring protection_string;
    TlsAnomalyType type = TlsAnomalyType::None;
    bool is_critical = false;
    std::wstring details;
};

struct TlsAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t modules_with_tls_count = 0;
    size_t total_callbacks_scanned = 0;
    size_t anomalous_callbacks_count = 0;
    std::vector<TlsAnomaly> anomalies;
};

class TlsAuditor {
public:
    static TlsAuditReport audit_process_tls(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::wstring anomaly_type_to_string(TlsAnomalyType type);

    // Pure evaluation function for unit testing and module analysis
    static std::vector<TlsAnomaly> evaluate_tls_module(
        uint64_t module_base,
        uint64_t module_size,
        const std::wstring& module_name,
        const std::vector<uint64_t>& callbacks,
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
