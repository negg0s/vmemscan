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

enum class ThreatVerdict {
    Clean,                // Score 0 - 20
    LowRisk,              // Score 21 - 45
    Suspicious,           // Score 46 - 75
    CriticalCompromised   // Score 76 - 100
};

struct RiskScoreBreakdown {
    uint32_t total_score = 0; // 0 - 100
    ThreatVerdict verdict = ThreatVerdict::Clean;
    std::wstring verdict_string;
    std::wstring recommended_action;
    std::vector<std::wstring> risk_factors;
};

class RiskScorer {
public:
    static RiskScoreBreakdown compute_process_risk(
        bool has_c2_beacon,
        bool is_hollowed,
        size_t direct_syscalls_count,
        size_t unbacked_threads_count,
        size_t security_patches_count,
        size_t unbacked_exec_count,
        size_t rwx_regions_count,
        size_t iat_hooks_count,
        size_t unlinked_modules_count,
        size_t high_entropy_regions_count,
        bool has_argument_spoofing,
        size_t unbacked_stack_frames_count = 0,
        size_t indirect_syscalls_count = 0,
        bool is_ghosted = false,
        size_t stomped_modules_count = 0,
        size_t sleep_masked_regions_count = 0,
        bool has_anti_debug = false,
        size_t wiped_pe_headers_count = 0,
        bool has_mitigation_breach = false,
        size_t veh_anomalies_count = 0,
        size_t thread_pool_anomalies_count = 0,
        size_t tls_anomalies_count = 0,
        size_t section_anomalies_count = 0,
        size_t unwind_anomalies_count = 0,
        size_t fiber_anomalies_count = 0,
        size_t clr_anomalies_count = 0
    );

    static std::wstring verdict_to_string(ThreatVerdict v);
};

} // namespace vmemscan
