#pragma once

#include "vmemscan/anti_debug_auditor.hpp"
#include "vmemscan/c2_detector.hpp"
#include "vmemscan/common.hpp"
#include "vmemscan/entropy_calculator.hpp"
#include "vmemscan/ghosting_detector.hpp"
#include "vmemscan/hook_detector.hpp"
#include "vmemscan/hollowing_detector.hpp"
#include "vmemscan/iat_hook_detector.hpp"
#include "vmemscan/indirect_syscall_auditor.hpp"
#include "vmemscan/injection_detector.hpp"
#include "vmemscan/ioc_extractor.hpp"
#include "vmemscan/ldr_auditor.hpp"
#include "vmemscan/memory_dumper.hpp"
#include "vmemscan/mitigations_auditor.hpp"
#include "vmemscan/module_auditor.hpp"
#include "vmemscan/module_stomping_detector.hpp"
#include "vmemscan/patch_detector.hpp"
#include "vmemscan/pattern_scanner.hpp"
#include "vmemscan/peb_auditor.hpp"
#include "vmemscan/risk_scorer.hpp"
#include "vmemscan/sleep_mask_detector.hpp"
#include "vmemscan/snapshot_differ.hpp"
#include "vmemscan/stack_auditor.hpp"
#include "vmemscan/syscall_auditor.hpp"
#include "vmemscan/thread_analyzer.hpp"
#include "vmemscan/thread_pool_auditor.hpp"
#include "vmemscan/tls_auditor.hpp"
#include "vmemscan/veh_auditor.hpp"
#include "vmemscan/wiped_pe_detector.hpp"

#include <string>
#include <vector>

namespace vmemscan {

class Formatter {
public:
    static void print_banner();
    static std::wstring format_bytes(uint64_t bytes);
    static std::wstring to_hex_string(uint64_t val, int width = 16);
    static std::wstring bytes_to_hex_preview(const std::vector<uint8_t>& bytes);

    static void print_process_list(const std::vector<ProcessInfo>& list);
    static void print_memory_map(const std::vector<MemoryRegion>& regions, size_t limit = 100);
    static void print_summary(const ProcessMemorySummary& s);
    static void print_injection_report(const ProcessInjectionReport& report);
    static void print_hook_report(const HookReport& report);
    static void print_patch_report(const PatchReport& report);
    static void print_hollowing_report(const HollowingReport& report);
    static void print_diff_report(const SnapshotDiffReport& report);
    static void print_entropy_report(const std::vector<EntropyReport>& reports);
    static void print_thread_report(const ThreadAuditReport& report);
    static void print_module_report(const ModuleAuditReport& report);
    static void print_c2_report(const C2ScanReport& report);
    static void print_peb_report(const PebAuditReport& report);
    static void print_ioc_report(const IocReport& report);
    static void print_syscall_report(const SyscallAuditReport& report);
    static void print_indirect_syscall_report(const IndirectSyscallReport& report);
    static void print_iat_report(const IatHookReport& report);
    static void print_stack_report(const StackAuditReport& report);
    static void print_ghosting_report(const GhostingReport& report);
    static void print_module_stomping_report(const ModuleStompingReport& report);
    static void print_sleep_mask_report(const SleepMaskReport& report);
    static void print_anti_debug_report(const AntiDebugReport& report);
    static void print_wiped_pe_report(const WipedPeReport& report);
    static void print_mitigations_report(const ProcessMitigationsReport& report);
    static void print_veh_report(const VehAuditReport& report);
    static void print_thread_pool_report(const ThreadPoolAuditReport& report);
    static void print_ldr_report(const LdrAuditReport& report);
    static void print_tls_report(const TlsAuditReport& report);
    static void print_risk_assessment(const ProcessInfo& proc, const RiskScoreBreakdown& risk);
    static void print_pattern_matches(const std::vector<PatternMatch>& matches);
    static void print_dump_result(const DumpResult& res);

    static std::string to_json(
        const ProcessInfo& proc,
        const ProcessMemorySummary& summary,
        const std::vector<MemoryRegion>& regions,
        const ProcessInjectionReport& injection
    );

    static std::string to_csv(const std::vector<MemoryRegion>& regions);
};

} // namespace vmemscan
