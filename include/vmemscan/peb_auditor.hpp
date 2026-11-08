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

enum class PebAnomalyType {
    None,
    ImagePathSpoofing,     // PEB ImagePathName does not match actual disk executable path
    EmptyCommandLine,      // Missing or zeroed command line in active user process
    DotNetProfilingHijack, // COR_ENABLE_PROFILING detected in environment block
    SuspiciousEnvironment  // Proxy, debug, or injection flags in environment
};

struct PebAnomaly {
    PebAnomalyType type = PebAnomalyType::None;
    std::wstring description;
    std::wstring expected_value;
    std::wstring actual_value;
    bool is_critical = false;
};

struct PebAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    uint64_t peb_address = 0;
    uint64_t process_parameters_address = 0;
    std::wstring image_path_name;
    std::wstring command_line;
    std::wstring current_directory;
    std::vector<std::wstring> suspicious_env_vars;
    std::vector<PebAnomaly> anomalies;
};

class PebAuditor {
public:
    static PebAuditReport audit_process_peb(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::wstring& real_image_path,
        bool is_64bit
    );

    static std::wstring anomaly_to_string(PebAnomalyType type);
};

} // namespace vmemscan
