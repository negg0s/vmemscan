#include "vmemscan/risk_scorer.hpp"

#include <algorithm>

namespace vmemscan {

std::wstring RiskScorer::verdict_to_string(ThreatVerdict v) {
    switch (v) {
    case ThreatVerdict::Clean:               return L"CLEAN (Normal Baseline)";
    case ThreatVerdict::LowRisk:             return L"LOW RISK (Minor Anomalies)";
    case ThreatVerdict::Suspicious:          return L"SUSPICIOUS (Possible In-Memory Evasion)";
    case ThreatVerdict::CriticalCompromised: return L"CRITICAL (Process Compromised / Active Implant)";
    default:                                 return L"Unknown";
    }
}

RiskScoreBreakdown RiskScorer::compute_process_risk(
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
    size_t unbacked_stack_frames_count,
    size_t indirect_syscalls_count,
    bool is_ghosted,
    size_t stomped_modules_count,
    size_t sleep_masked_regions_count,
    bool has_anti_debug
) {
    RiskScoreBreakdown r{};
    uint32_t score = 0;

    if (has_c2_beacon) {
        score += 50;
        r.risk_factors.push_back(L"Embedded C2 beacon configuration discovered (+50)");
    }

    if (sleep_masked_regions_count > 0) {
        score += 45;
        r.risk_factors.push_back(L"Sleep Mask obfuscation: Return address points into private non-executable page (+45)");
    }

    if (is_ghosted) {
        score += 45;
        r.risk_factors.push_back(L"Process Ghosting / Herpaderping backing file anomaly detected (+45)");
    }

    if (is_hollowed) {
        score += 45;
        r.risk_factors.push_back(L"Process Hollowing / PE EntryPoint divergence detected (+45)");
    }

    if (unbacked_stack_frames_count > 0) {
        score += 40;
        r.risk_factors.push_back(L"Thread call stack contains return address pointing to unbacked memory (+40)");
    }

    if (has_anti_debug) {
        score += 25;
        r.risk_factors.push_back(L"Anti-analysis / anti-debugging flags or hardware breakpoints active (+25)");
    }

    if (stomped_modules_count > 0) {
        score += 35;
        r.risk_factors.push_back(L"Module Stomping / loaded DLL code section overwrite detected (+35)");
    }

    if (indirect_syscalls_count > 0) {
        score += 35;
        r.risk_factors.push_back(L"Indirect syscall trampolines (Syswhispers3 / Hell's Hall) detected (+35)");
    }

    if (unbacked_threads_count > 0) {
        score += 35;
        r.risk_factors.push_back(L"Thread active instruction pointer executing in unbacked private memory (+35)");
    }

    if (direct_syscalls_count > 0) {
        score += 35;
        r.risk_factors.push_back(L"Direct syscall stubs (EDR bypass) identified outside NTDLL (+35)");
    }

    if (security_patches_count > 0) {
        score += 30;
        r.risk_factors.push_back(L"Security telemetry patches (ETW / AMSI silenced) detected (+30)");
    }

    if (has_argument_spoofing) {
        score += 25;
        r.risk_factors.push_back(L"PEB command-line or image path spoofing anomaly detected (+25)");
    }

    if (iat_hooks_count > 0) {
        score += 25;
        r.risk_factors.push_back(L"Import Address Table (IAT) hook redirected to private memory (+25)");
    }

    if (rwx_regions_count > 0) {
        score += 20;
        r.risk_factors.push_back(L"W^X policy breach: memory pages marked PAGE_EXECUTE_READWRITE (+20)");
    }

    if (unbacked_exec_count > 0) {
        score += 15;
        r.risk_factors.push_back(L"Executable private memory regions without disk backing allocated (+15)");
    }

    if (unlinked_modules_count > 0) {
        score += 15;
        r.risk_factors.push_back(L"Stealth loaded module unlinked from PEB InLoadOrderModuleList (+15)");
    }

    if (high_entropy_regions_count > 0) {
        score += 10;
        r.risk_factors.push_back(L"High-entropy executable memory pages (packed/encrypted code) (+10)");
    }

    r.total_score = (std::min)(score, 100u);

    if (r.total_score >= 76) {
        r.verdict = ThreatVerdict::CriticalCompromised;
        r.recommended_action = L"Immediate containment required. Terminate target process and investigate injection vector / C2 communications.";
    } else if (r.total_score >= 46) {
        r.verdict = ThreatVerdict::Suspicious;
        r.recommended_action = L"Isolate target process and capture a full memory dump for offline analysis. In-memory evasion mechanisms detected.";
    } else if (r.total_score >= 21) {
        r.verdict = ThreatVerdict::LowRisk;
        r.recommended_action = L"Monitor process activity. Observed anomalies may correspond to JIT compilers or legitimate security instrumentation.";
    } else {
        r.verdict = ThreatVerdict::Clean;
        r.recommended_action = L"No remediation required. Process memory execution profile is consistent with a clean baseline state.";
    }

    r.verdict_string = verdict_to_string(r.verdict);
    return r;
}

} // namespace vmemscan
