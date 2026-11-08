#pragma once

#include "vmemscan/c2_detector.hpp"
#include "vmemscan/common.hpp"
#include "vmemscan/entropy_calculator.hpp"
#include "vmemscan/hook_detector.hpp"
#include "vmemscan/hollowing_detector.hpp"
#include "vmemscan/injection_detector.hpp"
#include "vmemscan/ioc_extractor.hpp"
#include "vmemscan/memory_dumper.hpp"
#include "vmemscan/module_auditor.hpp"
#include "vmemscan/patch_detector.hpp"
#include "vmemscan/pattern_scanner.hpp"
#include "vmemscan/peb_auditor.hpp"
#include "vmemscan/snapshot_differ.hpp"
#include "vmemscan/thread_analyzer.hpp"

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
