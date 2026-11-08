#pragma once

#include "vmemscan/common.hpp"

#include <string>
#include <vector>

namespace vmemscan {

enum class AnomalySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

struct InjectionAnomaly {
    AnomalySeverity severity{AnomalySeverity::Medium};
    std::wstring type_name;
    uint64_t address{0};
    uint64_t size{0};
    std::wstring description;
    std::wstring details;
    bool has_pe_header{false};
    bool is_shellcode_signature{false};
    std::vector<uint8_t> header_preview;
};

struct ThreadAnomaly {
    uint32_t thread_id{0};
    uint64_t start_address{0};
    std::wstring region_type;
    std::wstring mapped_module;
    bool is_unbacked{false};
    bool is_suspicious{false};
    std::wstring description;
};

struct ProcessInjectionReport {
    uint32_t pid{0};
    std::wstring process_name;
    std::wstring process_path;
    bool is_64bit{true};
    size_t critical_anomalies_count{0};
    size_t high_anomalies_count{0};
    size_t medium_anomalies_count{0};
    bool has_process_hollowing{false};
    bool has_reflective_pe{false};
    bool has_unbacked_threads{false};

    std::vector<InjectionAnomaly> memory_anomalies;
    std::vector<ThreadAnomaly> thread_anomalies;
};

class InjectionDetector {
public:
    static ProcessInjectionReport analyze_process(
        HANDLE hProcess,
        const ProcessInfo& proc,
        const std::vector<MemoryRegion>& regions
    );

    static std::wstring severity_to_string(AnomalySeverity sev);
    static bool detect_shellcode_prolog(const uint8_t* data, size_t size);
};

} // namespace vmemscan
