#include "vmemscan/formatter.hpp"
#include "vmemscan/memory_scanner.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

namespace vmemscan {

void Formatter::print_banner() {
    std::wcout << L"======================================================================\n";
    std::wcout << L" vmemscan: Windows Virtual Memory & Process Injection Forensics\n";
    std::wcout << L"======================================================================\n\n";
}

std::wstring Formatter::format_bytes(uint64_t bytes) {
    std::wostringstream oss;
    oss << std::fixed << std::setprecision(2);
    if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
        oss << (static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0)) << L" GB";
    } else if (bytes >= 1024ULL * 1024ULL) {
        oss << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << L" MB";
    } else if (bytes >= 1024ULL) {
        oss << (static_cast<double>(bytes) / 1024.0) << L" KB";
    } else {
        oss << bytes << L" B";
    }
    return oss.str();
}

std::wstring Formatter::to_hex_string(uint64_t val, int width) {
    std::wostringstream oss;
    oss << L"0x" << std::hex << std::uppercase << std::setfill(L'0') << std::setw(width) << val;
    return oss.str();
}

std::wstring Formatter::bytes_to_hex_preview(const std::vector<uint8_t>& bytes) {
    std::wostringstream oss;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) oss << L" ";
        oss << std::hex << std::uppercase << std::setfill(L'0') << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

void Formatter::print_process_list(const std::vector<ProcessInfo>& list) {
    std::wcout << std::left
               << std::setw(8)  << L"PID"
               << std::setw(8)  << L"PPID"
               << std::setw(6)  << L"Arch"
               << std::setw(6)  << L"Admin"
               << std::right
               << std::setw(12) << L"WorkingSet"
               << std::setw(12) << L"Private"
               << L"  "
               << std::left
               << std::setw(24) << L"Image Name"
               << L"Path\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& p : list) {
        std::wcout << std::left
                   << std::setw(8)  << p.pid
                   << std::setw(8)  << p.parent_pid
                   << std::setw(6)  << (p.is_64bit ? L"x64" : L"x86")
                   << std::setw(6)  << (p.is_elevated ? L"Yes" : L"No")
                   << std::right
                   << std::setw(12) << format_bytes(p.working_set_bytes)
                   << std::setw(12) << format_bytes(p.commit_bytes)
                   << L"  "
                   << std::left
                   << std::setw(24) << p.name
                   << p.path << L"\n";
    }
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << L" Total processes: " << list.size() << L"\n\n";
}

void Formatter::print_memory_map(const std::vector<MemoryRegion>& regions, size_t limit) {
    std::wcout << std::left
               << std::setw(18) << L"Base Address"
               << std::right
               << std::setw(12) << L"Size"
               << L"  "
               << std::left
               << std::setw(8)  << L"State"
               << std::setw(8)  << L"Type"
               << std::setw(8)  << L"Protect"
               << std::setw(8)  << L"Flag"
               << L"Mapping\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    const size_t take = std::min(limit, regions.size());
    for (size_t i = 0; i < take; ++i) {
        const auto& r = regions[i];
        std::wstring flag = L"-";
        if (r.is_unbacked_executable) flag = L"UNBACKED";
        else if (r.is_rwx) flag = L"RWX";

        std::wcout << std::left
                   << std::setw(18) << to_hex_string(r.base_address, 12)
                   << std::right
                   << std::setw(12) << format_bytes(r.region_size)
                   << L"  "
                   << std::left
                   << std::setw(8)  << MemoryScanner::state_to_string(r.state)
                   << std::setw(8)  << MemoryScanner::type_to_string(r.type)
                   << std::setw(8)  << MemoryScanner::protect_to_string(r.protect)
                   << std::setw(8)  << flag
                   << r.mapped_file << L"\n";
    }

    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << L" Displaying " << take << L" of " << regions.size() << L" committed memory regions\n\n";
}

void Formatter::print_summary(const ProcessMemorySummary& s) {
    std::wcout << L"============================================================\n";
    std::wcout << L" PROCESS VIRTUAL MEMORY SUMMARY: " << s.process_name << L" (PID " << s.pid << L")\n";
    std::wcout << L"============================================================\n";
    std::wcout << L"  Total Committed Memory   : " << format_bytes(s.total_committed_bytes) << L" (" << s.committed_regions << L" regions)\n";
    std::wcout << L"  Private Commit (Heaps)   : " << format_bytes(s.total_private_bytes) << L"\n";
    std::wcout << L"  Image Commit (DLLs/EXE)  : " << format_bytes(s.total_image_bytes) << L"\n";
    std::wcout << L"  Mapped Files Commit      : " << format_bytes(s.total_mapped_bytes) << L"\n";
    std::wcout << L"------------------------------------------------------------\n";
    std::wcout << L"  Total Executable Memory  : " << format_bytes(s.executable_bytes) << L"\n";
    std::wcout << L"  Unbacked Executable      : " << format_bytes(s.unbacked_executable_bytes)
               << L" (" << s.unbacked_executable_regions_count << L" regions) ";
    if (s.unbacked_executable_regions_count > 0) std::wcout << L"[SUSPICIOUS]";
    std::wcout << L"\n";
    std::wcout << L"  RWX Memory (W^X Breach)  : " << format_bytes(s.rwx_bytes)
               << L" (" << s.rwx_regions_count << L" regions) ";
    if (s.rwx_regions_count > 0) std::wcout << L"[SUSPICIOUS]";
    std::wcout << L"\n";
    std::wcout << L"============================================================\n\n";
}

void Formatter::print_injection_report(const ProcessInjectionReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" PROCESS INJECTION & CODE ANOMALY AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Critical Alerts : " << report.critical_anomalies_count << L"\n";
    std::wcout << L"  High Alerts     : " << report.high_anomalies_count << L"\n";
    std::wcout << L"  Medium Alerts   : " << report.medium_anomalies_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.memory_anomalies.empty() && report.thread_anomalies.empty()) {
        std::wcout << L"  Zero injection signatures or unbacked executable memory regions detected.\n";
    } else {
        for (const auto& a : report.memory_anomalies) {
            std::wcout << L"  [" << InjectionDetector::severity_to_string(a.severity) << L"] "
                       << a.type_name << L" at " << to_hex_string(a.address, 12)
                       << L" (" << format_bytes(a.size) << L")\n";
            std::wcout << L"    Description : " << a.description << L"\n";
            if (!a.details.empty()) {
                std::wcout << L"    Details     : " << a.details << L"\n";
            }
            if (!a.header_preview.empty()) {
                std::wcout << L"    Preview     : " << bytes_to_hex_preview(a.header_preview) << L"\n";
            }
            std::wcout << L"\n";
        }

        for (const auto& ta : report.thread_anomalies) {
            std::wcout << L"  [CRITICAL] Suspicious Thread Execution (TID " << ta.thread_id << L")\n";
            std::wcout << L"    Start Address : " << to_hex_string(ta.start_address, 12) << L"\n";
            std::wcout << L"    Memory Type   : " << ta.region_type << L"\n";
            std::wcout << L"    Module        : " << ta.mapped_module << L"\n";
            std::wcout << L"    Description   : " << ta.description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_hook_report(const HookReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" USER-MODE API INLINE HOOK AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Inspected System APIs : " << report.inspected_functions_count << L"\n";
    std::wcout << L"  Detected Hooks        : " << report.detected_hooks_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.hooks.empty()) {
        std::wcout << L"  Zero inline hooks detected. All checked system APIs begin with clean syscall stubs.\n";
    } else {
        for (const auto& h : report.hooks) {
            std::wcout << L"  Function   : " << h.module_name << L"!" << std::wstring(h.function_name.begin(), h.function_name.end()) << L"\n";
            std::wcout << L"  Address    : " << to_hex_string(h.function_address, 12) << L"\n";
            std::wcout << L"  Hook Type  : " << h.hook_type << L"\n";
            std::wcout << L"  Destination: " << to_hex_string(h.hook_target_address, 12) << L" [" << h.target_module << L"]\n";
            std::wcout << L"  Memory Hex : " << bytes_to_hex_preview(h.memory_bytes) << L"\n";
            if (!h.original_bytes.empty()) {
                std::wcout << L"  Clean Hex  : " << bytes_to_hex_preview(h.original_bytes) << L"\n";
            }
            std::wcout << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_pattern_matches(const std::vector<PatternMatch>& matches) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" MEMORY PATTERN MATCHES (" << matches.size() << L" results)\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << std::left
               << std::setw(18) << L"Address"
               << std::setw(10) << L"Type"
               << std::setw(10) << L"Protect"
               << L"Preview Bytes\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& m : matches) {
        std::wcout << std::left
                   << std::setw(18) << to_hex_string(m.address, 12)
                   << std::setw(10) << m.region_type
                   << std::setw(10) << m.region_protect
                   << bytes_to_hex_preview(m.preview_bytes) << L"\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_dump_result(const DumpResult& res) {
    std::wcout << L"============================================================\n";
    std::wcout << L" MEMORY REGION DUMP RESULT\n";
    std::wcout << L"============================================================\n";
    std::wcout << L"  Process PID      : " << res.pid << L"\n";
    std::wcout << L"  Base Address     : " << to_hex_string(res.base_address, 12) << L"\n";
    std::wcout << L"  Bytes Dumped     : " << format_bytes(res.bytes_dumped) << L" (" << res.bytes_dumped << L" bytes)\n";
    std::wcout << L"  Output File      : " << res.output_path << L"\n";
    std::wcout << L"  PE Header Found  : " << (res.is_pe_image ? L"Yes (MZ signature)" : L"No") << L"\n";
    std::wcout << L"  PE Reconstructed : " << (res.pe_reconstructed ? L"Yes (sections aligned for static tools)" : L"No") << L"\n";
    std::wcout << L"  FNV-1a Hash      : 0x" << std::hex << std::uppercase << res.fnv1a_hash << std::dec << L"\n";
    std::wcout << L"============================================================\n\n";
}

void Formatter::print_patch_report(const PatchReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" SECURITY TELEMETRY & API PATCH AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Inspected Telemetry Stubs : " << report.inspected_targets_count << L"\n";
    std::wcout << L"  Detected Patches / Bypasses: " << report.anomalies.size() << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero security patches detected. All inspected ETW and AMSI entry points are untampered.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [" << (a.is_critical ? L"CRITICAL" : L"WARNING") << L"] "
                       << a.module_name << L"!" << std::wstring(a.function_name.begin(), a.function_name.end())
                       << L" at " << to_hex_string(a.virtual_address) << L"\n";
            std::wcout << L"    Classification: " << PatchDetector::patch_type_to_string(a.patch_type) << L"\n";
            std::wcout << L"    Details       : " << a.patch_description << L"\n";
            std::wcout << L"    Prologue Hex  : " << bytes_to_hex_preview(a.prologue_bytes) << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_hollowing_report(const HollowingReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" PROCESS HOLLOWING & MODULE OVERWRITE AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  PEB Address               : " << to_hex_string(report.peb_address) << L"\n";
    std::wcout << L"  In-Memory ImageBase       : " << to_hex_string(report.in_memory_image_base) << L"\n";
    std::wcout << L"  In-Memory EntryPoint      : " << to_hex_string(report.in_memory_entry_point) << L"\n";
    if (report.on_disk_entry_point != 0) {
        std::wcout << L"  On-Disk EntryPoint RVA    : " << to_hex_string(report.on_disk_entry_point, 8) << L"\n";
    }
    std::wcout << L"  Hollowing Status          : " << (report.is_hollowed ? L"[DETECTED] Process appears hollowed" : L"Clean (Consistent with disk)") << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero hollowing anomalies detected. PE headers and entry point match the on-disk binary.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [" << (a.is_critical ? L"CRITICAL" : L"WARNING") << L"] "
                       << HollowingDetector::anomaly_type_to_string(a.type) << L"\n";
            std::wcout << L"    Details       : " << a.description << L"\n";
            if (a.expected_value != 0 || a.actual_value != 0) {
                std::wcout << L"    Expected      : " << to_hex_string(a.expected_value)
                           << L" | Actual: " << to_hex_string(a.actual_value) << L"\n";
            }
            if (!a.preview_bytes.empty()) {
                std::wcout << L"    Bytes Preview : " << bytes_to_hex_preview(a.preview_bytes) << L"\n";
            }
            std::wcout << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_diff_report(const SnapshotDiffReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" PROCESS MEMORY SNAPSHOT DIFF REPORT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  New Executable Regions    : " << report.new_executable_regions.size() << L"\n";
    std::wcout << L"  Protection Escalations    : " << report.protection_escalations.size() << L"\n";
    std::wcout << L"  Modified Code Regions     : " << report.modified_code_regions.size() << L"\n";
    std::wcout << L"  Deallocated Regions       : " << report.deallocated_regions.size() << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (!report.new_executable_regions.empty()) {
        std::wcout << L"\n  -- NEW EXECUTABLE REGIONS (Possible Late Injections / Shellcode) --\n";
        for (const auto& r : report.new_executable_regions) {
            std::wcout << L"    Base: " << to_hex_string(r.base_address)
                       << L" (" << format_bytes(r.region_size) << L") Protect: "
                       << MemoryScanner::protect_to_string(r.protect) << L"\n";
        }
    }

    if (!report.protection_escalations.empty()) {
        std::wcout << L"\n  -- PROTECTION ESCALATIONS (W^X Violations / Page Modification) --\n";
        for (const auto& pe : report.protection_escalations) {
            std::wcout << L"    Base: " << to_hex_string(pe.base_address)
                       << L" (" << format_bytes(pe.region_size) << L") Old: "
                       << MemoryScanner::protect_to_string(pe.old_protect)
                       << L" -> New: " << MemoryScanner::protect_to_string(pe.new_protect) << L"\n";
        }
    }

    if (!report.modified_code_regions.empty()) {
        std::wcout << L"\n  -- MODIFIED CODE REGIONS (Inline Code Patches / Hooks) --\n";
        for (const auto& mc : report.modified_code_regions) {
            std::wcout << L"    Base: " << to_hex_string(mc.base_address)
                       << L" (" << format_bytes(mc.region_size) << L") Hash Changed: "
                       << to_hex_string(mc.old_hash, 16) << L" -> " << to_hex_string(mc.new_hash, 16) << L"\n";
        }
    }

    if (report.new_executable_regions.empty() && report.protection_escalations.empty() && report.modified_code_regions.empty()) {
        std::wcout << L"  Zero unexpected memory anomalies detected compared to baseline snapshot.\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_entropy_report(const std::vector<EntropyReport>& reports) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" MEMORY ENTROPY ANALYSIS (PACKED / ENCRYPTED BUFFER DETECTION)\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << std::left << std::setw(18) << L"Base Address"
               << std::setw(12) << L"Size"
               << std::setw(10) << L"Protect"
               << std::setw(10) << L"Entropy"
               << std::setw(24) << L"Classification"
               << L"Mapped File / Tag\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    size_t high_count = 0;
    for (const auto& r : reports) {
        if (r.is_high_entropy) ++high_count;
        std::wostringstream ent_str;
        ent_str << std::fixed << std::setprecision(2) << r.entropy;

        std::wstring classification = r.is_high_entropy ? L"HIGH (Encrypted/Packed)" : (r.is_unbacked ? L"Unbacked Executable" : L"Normal Code");
        std::wstring tag = r.mapped_file.empty() ? (r.is_unbacked ? L"[PRIVATE EXECUTABLE]" : L"[HEAP / ANONYMOUS]") : r.mapped_file;

        std::wcout << std::left << std::setw(18) << to_hex_string(r.base_address)
                   << std::setw(12) << format_bytes(r.region_size)
                   << std::setw(10) << MemoryScanner::protect_to_string(r.protect)
                   << std::setw(10) << ent_str.str()
                   << std::setw(24) << classification
                   << tag << L"\n";
    }

    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << L" Total regions evaluated: " << reports.size() << L" | High entropy regions (>= 7.20): " << high_count << L"\n";
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_thread_report(const ThreadAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" THREAD EXECUTION & INSTRUCTION POINTER AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Total Threads Inspected   : " << report.total_threads << L"\n";
    std::wcout << L"  Suspicious Threads Count  : " << report.suspicious_threads_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.suspicious_threads_count == 0) {
        std::wcout << L"  Zero suspicious threads detected. All threads start and execute inside mapped image modules.\n";
    } else {
        for (const auto& t : report.threads) {
            if (t.anomalies.empty()) continue;

            std::wcout << L"  [THREAD ANOMALY] Thread ID: " << t.thread_id << L"\n";
            std::wcout << L"    Start Address : " << to_hex_string(t.start_address)
                       << (t.start_module.empty() ? L" [UNBACKED PRIVATE MEMORY]" : (L" (" + t.start_module + L")")) << L"\n";
            std::wcout << L"    Current RIP   : " << to_hex_string(t.rip)
                       << (t.rip_module.empty() ? L" [UNBACKED PRIVATE MEMORY]" : (L" (" + t.rip_module + L")")) << L"\n";
            for (const auto& an : t.anomalies) {
                std::wcout << L"    Alert         : " << ThreadAnalyzer::anomaly_to_string(an) << L"\n";
            }
            if (!t.rip_bytes_preview.empty()) {
                std::wcout << L"    RIP Preview   : " << bytes_to_hex_preview(t.rip_bytes_preview) << L"\n";
            }
            std::wcout << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_module_report(const ModuleAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" LOADED MODULES & STEALTH UNLINKING AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Total Modules Enumerated  : " << report.total_modules << L"\n";
    std::wcout << L"  Anomalous Modules Detected: " << report.anomalous_modules_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left << std::setw(18) << L"Base Address"
               << std::setw(12) << L"Size"
               << std::setw(8)  << L"In PEB"
               << std::setw(24) << L"Module Name"
               << L"Module Path\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& m : report.modules) {
        std::wcout << std::left << std::setw(18) << to_hex_string(m.base_address)
                   << std::setw(12) << format_bytes(m.size_of_image)
                   << std::setw(8)  << (m.in_peb_list ? L"Yes" : L"NO [!]")
                   << std::setw(24) << m.module_name
                   << m.module_path << L"\n";
        for (const auto& an : m.anomalies) {
            std::wcout << L"    >> Alert: " << ModuleAuditor::anomaly_to_string(an) << L"\n";
        }
    }

    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_c2_report(const C2ScanReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" COMMAND & CONTROL (C2) BEACON CONFIGURATION SCAN: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Memory Regions Evaluated  : " << report.regions_scanned << L"\n";
    std::wcout << L"  C2 Beacons Discovered     : " << report.detected_beacons.size() << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.detected_beacons.empty()) {
        std::wcout << L"  Zero known C2 beacon configurations detected in committed memory regions.\n";
    } else {
        for (const auto& b : report.detected_beacons) {
            std::wcout << L"  [DETECTED C2 ARTIFACT] " << b.framework_name << L" at " << to_hex_string(b.virtual_address) << L"\n";
            std::wcout << L"    XOR Key       : 0x" << std::hex << static_cast<uint32_t>(b.xor_key) << std::dec << L"\n";
            if (!b.c2_server.empty())        std::wcout << L"    C2 Server     : " << b.c2_server << L"\n";
            if (b.c2_port != 0)              std::wcout << L"    C2 Port       : " << b.c2_port << L"\n";
            if (b.sleep_time_ms != 0)        std::wcout << L"    Sleep Time    : " << b.sleep_time_ms << L" ms (Jitter: " << b.jitter_percent << L"%)\n";
            if (!b.http_user_agent.empty())  std::wcout << L"    User-Agent    : " << b.http_user_agent << L"\n";
            if (!b.http_post_uri.empty())    std::wcout << L"    Post URI      : " << b.http_post_uri << L"\n";
            if (!b.named_pipe.empty())       std::wcout << L"    Named Pipe    : " << b.named_pipe << L"\n";
            if (!b.spawnto_process.empty())  std::wcout << L"    Spawnto Target: " << b.spawnto_process << L"\n";
            if (b.watermark != 0)            std::wcout << L"    Watermark ID  : " << b.watermark << L"\n";
            std::wcout << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_peb_report(const PebAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" PEB & PROCESS PARAMETERS AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  PEB Address               : " << to_hex_string(report.peb_address) << L"\n";
    std::wcout << L"  ProcessParameters Address : " << to_hex_string(report.process_parameters_address) << L"\n";
    std::wcout << L"  ImagePathName (PEB)       : " << report.image_path_name << L"\n";
    std::wcout << L"  CommandLine (PEB)         : " << report.command_line << L"\n";
    std::wcout << L"  CurrentDirectory          : " << report.current_directory << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty() && report.suspicious_env_vars.empty()) {
        std::wcout << L"  Zero PEB anomalies detected. ImagePathName and environment blocks are consistent.\n";
    } else {
        for (const auto& an : report.anomalies) {
            std::wcout << L"  [ALERT] " << PebAuditor::anomaly_to_string(an.type) << L"\n";
            std::wcout << L"    Details : " << an.description << L"\n";
            if (!an.expected_value.empty()) std::wcout << L"    Expected: " << an.expected_value << L"\n";
            if (!an.actual_value.empty())   std::wcout << L"    Actual  : " << an.actual_value << L"\n";
            std::wcout << L"\n";
        }
        for (const auto& env : report.suspicious_env_vars) {
            std::wcout << L"  [SUSPICIOUS ENV VAR] " << env << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_ioc_report(const IocReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" MEMORY IOC & STRING EXTRACTION REPORT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Target Virtual Address    : " << to_hex_string(report.target_address) << L"\n";
    std::wcout << L"  Total IOC Artifacts Found : " << report.total_strings_found << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left << std::setw(18) << L"Address"
               << std::setw(28) << L"IOC Classification"
               << std::setw(10) << L"Encoding"
               << L"Extracted Value\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& art : report.artifacts) {
        std::wcout << std::left << std::setw(18) << to_hex_string(art.virtual_address)
                   << std::setw(28) << IocExtractor::ioc_type_to_string(art.type)
                   << std::setw(10) << (art.is_unicode ? L"UTF-16" : L"ASCII")
                   << art.value << L"\n";
    }

    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_syscall_report(const SyscallAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" DIRECT SYSCALL & EDR BYPASS AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Executable Regions Checked: " << report.regions_evaluated << L"\n";
    std::wcout << L"  Direct Syscalls Discovered: " << report.anomalies_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies_count == 0) {
        std::wcout << L"  Zero direct syscall stubs detected. System calls originate strictly from ntdll.dll / win32u.dll.\n";
    } else {
        for (const auto& s : report.findings) {
            std::wcout << L"  [DETECTED DIRECT SYSCALL] Address: " << to_hex_string(s.virtual_address) << L"\n";
            std::wcout << L"    Stub Type   : " << s.stub_type << L"\n";
            if (s.ssn != 0) {
                std::wcout << L"    Syscall SSN : 0x" << std::hex << s.ssn << std::dec << L" (Decimal: " << s.ssn << L")\n";
            }
            std::wcout << L"    Memory Type : " << (s.is_unbacked ? L"UNBACKED PRIVATE MEMORY [!]" : (s.mapped_module.empty() ? L"Anonymous" : s.mapped_module)) << L"\n";
            if (s.is_rwx) {
                std::wcout << L"    Protection  : PAGE_EXECUTE_READWRITE [W^X BREACH]\n";
            }
            if (!s.instruction_bytes.empty()) {
                std::wcout << L"    Hex Bytes   : " << bytes_to_hex_preview(s.instruction_bytes) << L"\n";
            }
            std::wcout << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_iat_report(const IatHookReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" IMPORT ADDRESS TABLE (IAT) HOOK AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Total Imports Verified    : " << report.total_imports_checked << L"\n";
    std::wcout << L"  Hooked / Divergent Entries: " << report.hooked_imports_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.hooked_imports_count == 0) {
        std::wcout << L"  Zero IAT hooks detected. All imported function pointers resolve to clean system module ranges.\n";
    } else {
        for (const auto& h : report.findings) {
            std::wcout << L"  [IAT HOOK DETECTED] " << h.imported_module << L"!" << std::wstring(h.function_name.begin(), h.function_name.end()) << L"\n";
            std::wcout << L"    IAT Entry Address : " << to_hex_string(h.iat_entry_address) << L"\n";
            std::wcout << L"    Actual Pointer    : " << to_hex_string(h.actual_function_pointer)
                       << (h.points_to_unbacked ? L" [POINTS TO UNBACKED PRIVATE MEMORY]" : L"")
                       << (h.points_to_rwx ? L" [RWX PAGE]" : L"") << L"\n";
            if (!h.actual_mapped_module.empty()) {
                std::wcout << L"    Resolved Module   : " << h.actual_mapped_module << L"\n";
            }
            std::wcout << L"    Details           : " << h.hook_description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_indirect_syscall_report(const IndirectSyscallReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" INDIRECT SYSCALL & TRAMPOLINE AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Executable Regions Evaluated: " << report.regions_evaluated << L"\n";
    std::wcout << L"  Indirect Syscall Trampolines: " << report.anomalies_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies_count == 0) {
        std::wcout << L"  Zero indirect syscall trampolines detected. No user-mode JMP evasion stubs found.\n";
    } else {
        for (const auto& f : report.findings) {
            std::wcout << L"  [INDIRECT SYSCALL DETECTED] Address: " << to_hex_string(f.virtual_address) << L"\n";
            std::wcout << L"    Technique   : " << f.technique_name << L"\n";
            std::wcout << L"    Syscall SSN : 0x" << std::hex << f.ssn << std::dec << L" (Decimal: " << f.ssn << L")\n";
            std::wcout << L"    Jump Target : " << to_hex_string(f.target_address) << L"\n";
            if (!f.target_module.empty()) {
                std::wcout << L"    Target Mod  : " << f.target_module << L"\n";
            }
            std::wcout << L"    Memory Type : " << (f.is_unbacked ? L"UNBACKED PRIVATE MEMORY [!]" : (f.mapped_module.empty() ? L"Anonymous" : f.mapped_module)) << L"\n";
            if (f.is_rwx) {
                std::wcout << L"    Protection  : PAGE_EXECUTE_READWRITE [W^X BREACH]\n";
            }
            if (!f.instruction_bytes.empty()) {
                std::wcout << L"    Hex Bytes   : " << bytes_to_hex_preview(f.instruction_bytes) << L"\n";
            }
            std::wcout << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_stack_report(const StackAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" THREAD CALL STACK & RETURN ADDRESS AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Threads Inspected         : " << report.threads_inspected << L"\n";
    std::wcout << L"  Stack Pointer Slots Walked: " << report.total_frames_scanned << L"\n";
    std::wcout << L"  Unbacked Return Addresses : " << report.unbacked_frames_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.unbacked_frames_count == 0) {
        std::wcout << L"  Zero unbacked stack frames detected. All return pointers resolve to mapped library files.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [UNBACKED STACK FRAME] Thread TID: " << a.thread_id << L"\n";
            std::wcout << L"    Stack Address     : " << to_hex_string(a.stack_slot_address) << L"\n";
            std::wcout << L"    Return Address    : " << to_hex_string(a.return_address)
                       << (a.is_unbacked ? L" [UNBACKED PRIVATE MEMORY]" : L"")
                       << (a.is_rwx ? L" [PAGE_EXECUTE_READWRITE]" : L"") << L"\n";
            if (!a.mapped_module.empty()) {
                std::wcout << L"    Resolved Module   : " << a.mapped_module << L"\n";
            }
            std::wcout << L"    Anomaly Details   : " << a.anomaly_description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_ghosting_report(const GhostingReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" PROCESS GHOSTING & FILE TAMPERING AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Backing Disk Path : " << (report.disk_path.empty() ? L"Unknown" : report.disk_path) << L"\n";
    std::wcout << L"  Ghosting Status   : " << (report.is_ghosted ? L"DETECTED (Backing file deleted / DeletePending active) [!]" : L"Clean (Disk file intact)") << L"\n";
    std::wcout << L"  Herpaderping      : " << (report.is_herpaderped ? L"DETECTED (Disk content replaced post-mapping) [!]" : L"Clean (Headers match disk)") << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero process ghosting or herpaderping anomalies detected. Backing executable file is verified.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [" << (a.is_critical ? L"CRITICAL GHOSTING ANOMALY" : L"GHOSTING WARNING") << L"] " << a.anomaly_type << L"\n";
            std::wcout << L"    Disk Path : " << a.disk_path << L"\n";
            std::wcout << L"    Details   : " << a.details << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_module_stomping_report(const ModuleStompingReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" MODULE STOMPING & CODE SECTION INTEGRITY AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Loaded Modules Evaluated: " << report.modules_evaluated << L"\n";
    std::wcout << L"  Stomped Modules Detected: " << report.stomped_modules_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.stomped_modules_count == 0) {
        std::wcout << L"  Zero module stomping anomalies detected. Code sections match clean on-disk files.\n";
    } else {
        for (const auto& f : report.findings) {
            std::wcout << L"  [STOMPED MODULE DETECTED] " << f.module_name << L"\n";
            std::wcout << L"    Base Address      : " << to_hex_string(f.module_base) << L"\n";
            std::wcout << L"    Section Name      : " << std::wstring(f.section_name.begin(), f.section_name.end()) << L"\n";
            std::wcout << L"    Section Address   : " << to_hex_string(f.section_address) << L"\n";
            std::wcout << L"    Divergent Bytes   : " << f.bytes_divergent << L" bytes altered\n";
            std::wcout << L"    Anomaly Type      : " << f.stomping_type << L"\n";
            if (!f.in_memory_bytes.empty()) {
                std::wcout << L"    In-Memory Bytes   : " << bytes_to_hex_preview(f.in_memory_bytes) << L"\n";
            }
            if (!f.on_disk_bytes.empty()) {
                std::wcout << L"    On-Disk Bytes     : " << bytes_to_hex_preview(f.on_disk_bytes) << L"\n";
            }
            std::wcout << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_sleep_mask_report(const SleepMaskReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" SLEEP MASK & DORMANT PAYLOAD FORENSICS: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Sleeping Threads Inspected  : " << report.sleeping_threads_scanned << L"\n";
    std::wcout << L"  Masked / Demoted Regions    : " << report.masked_regions_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.masked_regions_count == 0) {
        std::wcout << L"  Zero sleep mask anomalies detected. No dormant non-executable stack return addresses found.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [SLEEP MASK DETECTED] Thread TID: " << a.thread_id << L"\n";
            std::wcout << L"    Return Address    : " << to_hex_string(a.wait_return_address) << L"\n";
            std::wcout << L"    Target Page Base  : " << to_hex_string(a.target_region_base) << L"\n";
            std::wcout << L"    Page Size         : " << format_bytes(a.target_region_size) << L"\n";
            std::wcout << L"    Current Protection: " << a.protection_string << L" [DEMOTED TO HIDE EXECUTABLE CODE]\n";
            std::wcout << L"    Details           : " << a.anomaly_description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_anti_debug_report(const AntiDebugReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" ANTI-DEBUGGING & PROCESS INSTRUMENTATION AUDIT: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Kernel Debugger Active     : " << (report.kernel_debugger_present ? L"TRUE [!]" : L"False") << L"\n";
    std::wcout << L"  PEB BeingDebugged Flag     : " << (report.peb_being_debugged ? L"TRUE [!]" : L"False") << L"\n";
    std::wcout << L"  Hardware Breakpoints (DR)  : " << (report.hardware_breakpoints_present ? L"ACTIVE (VEH Hooking / Evasion) [!]" : L"Clean") << L"\n";
    std::wcout << L"  Anti-Analysis Flags        : " << (report.anti_debug_flags_detected ? L"DETECTED (NtGlobalFlag / DebugFlags altered) [!]" : L"Clean") << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.findings.empty()) {
        std::wcout << L"  Zero anti-debugging flags or hardware breakpoints active. Normal process execution state.\n";
    } else {
        for (const auto& f : report.findings) {
            std::wcout << L"  [" << (f.is_anti_debug ? L"ANTI-ANALYSIS FLAG" : L"DEBUG INDICATOR") << L"] " << f.category << L" - " << f.indicator_name << L"\n";
            std::wcout << L"    Value   : " << to_hex_string(f.value) << L"\n";
            std::wcout << L"    Details : " << f.details << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_wiped_pe_report(const WipedPeReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" WIPED & OBFUSCATED PE HEADER FORENSICS: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Regions Evaluated         : " << report.regions_scanned << L"\n";
    std::wcout << L"  Wiped PE Headers Detected : " << report.wiped_pe_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.wiped_pe_count == 0) {
        std::wcout << L"  Zero wiped PE headers detected. No hidden in-memory PE structures found.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [WIPED PE DETECTED] Region Base: " << to_hex_string(a.region_base) << L"\n";
            std::wcout << L"    NT Headers Offset : +" << to_hex_string(a.nt_headers_offset, 4) << L"\n";
            std::wcout << L"    Architecture      : 0x" << std::hex << a.machine_architecture << std::dec;
            if (a.machine_architecture == IMAGE_FILE_MACHINE_AMD64) std::wcout << L" (x64 / AMD64)";
            else if (a.machine_architecture == IMAGE_FILE_MACHINE_I386) std::wcout << L" (x86 / i386)";
            else if (a.machine_architecture == IMAGE_FILE_MACHINE_ARM64) std::wcout << L" (ARM64)";
            std::wcout << L"\n";
            std::wcout << L"    Sections          : " << a.section_count << L"\n";
            std::wcout << L"    Memory Protection : " << a.protection_string << L"\n";
            std::wcout << L"    DOS Magic Wiped   : " << (a.dos_header_wiped ? L"TRUE (MZ signature erased) [!]" : L"False") << L"\n";
            std::wcout << L"    Section Names     : " << (a.section_names_scrambled ? L"SCRAMBLED / OBFUSCATED [!]" : L"Standard") << L"\n";
            std::wcout << L"    Details           : " << a.anomaly_description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_mitigations_report(const ProcessMitigationsReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" PROCESS SECURITY MITIGATIONS & EXPLOIT DEFENSE: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Data Execution Prevention (DEP) : " << (report.dep_enabled ? L"Enforced" : L"DISABLED [!]") << L"\n";
    std::wcout << L"  Control Flow Guard (CFG)        : " << (report.cfg_enabled ? L"Enforced" : L"Disabled") << L"\n";
    std::wcout << L"  Arbitrary Code Guard (ACG)      : " << (report.acg_prohibit_dynamic_code ? L"Enforced (Dynamic Code Prohibited)" : L"Disabled (Dynamic Code Permitted)") << L"\n";
    std::wcout << L"  Microsoft Binaries Only         : " << (report.msft_signed_only ? L"Enforced" : L"Standard") << L"\n";
    std::wcout << L"  Remote Images Blocked           : " << (report.no_remote_images ? L"Enforced" : L"Permitted") << L"\n";
    std::wcout << L"  Child Processes Blocked         : " << (report.no_child_processes ? L"Blocked" : L"Permitted") << L"\n";
    std::wcout << L"  Strict Handle Checks            : " << (report.strict_handle_checks ? L"Enforced" : L"Standard") << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.policies.empty()) {
        std::wcout << L"  Unable to query process mitigation policies (Insufficient privileges or system process).\n";
    } else {
        std::wcout << L"  Active Exploit Mitigation Policies:\n";
        for (const auto& p : report.policies) {
            std::wcout << L"    [*] " << p.policy_name << L": " << p.status_text << L"\n";
            std::wcout << L"        " << p.description << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_veh_report(const VehAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" VECTORED EXCEPTION HANDLING (VEH) & PAGE GUARD FORENSICS: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Regions Evaluated         : " << report.regions_evaluated << L"\n";
    std::wcout << L"  PAGE_GUARD Traps Active   : " << report.guard_page_traps_count << L"\n";
    std::wcout << L"  Anomalous VEH Handlers    : " << report.anomalous_handlers_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero VEH anomalies or PAGE_GUARD traps detected. Normal exception dispatch state.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [EXCEPTION ANOMALY DETECTED] Target Address: " << to_hex_string(a.target_address) << L"\n";
            std::wcout << L"    Anomaly Type      : " << a.anomaly_type << L"\n";
            if (!a.mapped_module.empty()) {
                std::wcout << L"    Module            : " << a.mapped_module << L"\n";
            }
            std::wcout << L"    Memory Protection : " << a.protection_string << L"\n";
            std::wcout << L"    Details           : " << a.details << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_thread_pool_report(const ThreadPoolAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" THREAD POOL & ASYNCHRONOUS WORK ITEM FORENSICS: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Worker Threads Inspected  : " << report.pool_workers_scanned << L"\n";
    std::wcout << L"  Callback Anomalies Found  : " << report.pool_anomalies_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.pool_anomalies_count == 0) {
        std::wcout << L"  Zero thread pool callback anomalies detected. All worker dispatch targets resolve to clean modules.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [THREAD POOL INJECTION DETECTED] Thread TID: " << a.thread_id << L"\n";
            std::wcout << L"    Worker Start Address : " << to_hex_string(a.worker_start_address) << L"\n";
            std::wcout << L"    Callback Address     : " << to_hex_string(a.callback_address) << L"\n";
            if (!a.callback_module.empty()) {
                std::wcout << L"    Callback Module      : " << a.callback_module << L"\n";
            }
            std::wcout << L"    Memory Protection    : " << a.protection_string << L"\n";
            std::wcout << L"    Details              : " << a.anomaly_description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_ldr_report(const LdrAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" PEB LOADER & UNLINKED MODULE FORENSICS: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Registered PEB Modules    : " << report.peb_modules_count << L"\n";
    std::wcout << L"  Mapped MEM_IMAGE Regions  : " << report.mapped_images_count << L"\n";
    std::wcout << L"  Unlinked (Hidden) Modules : " << report.unlinked_count << L"\n";
    std::wcout << L"  Phantom PEB Entries       : " << report.phantom_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero PEB loader anomalies detected. All mapped PE images match registered PEB loader entries.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [" << (a.is_critical ? L"CRITICAL PEB ANOMALY" : L"PEB DESYNC WARNING") << L"] "
                       << L"Module Base: " << to_hex_string(a.module_base) << L"\n";
            std::wcout << L"    Anomaly Type      : " << LdrAuditor::anomaly_type_to_string(a.type) << L"\n";
            if (!a.module_name.empty()) {
                std::wcout << L"    Module Name       : " << a.module_name << L"\n";
            }
            if (!a.module_path.empty()) {
                std::wcout << L"    Module Path       : " << a.module_path << L"\n";
            }
            if (a.size_of_image > 0) {
                std::wcout << L"    Size of Image     : 0x" << std::hex << a.size_of_image << std::dec << L" (" << format_bytes(a.size_of_image) << L")\n";
            }
            std::wcout << L"    Details           : " << a.anomaly_description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_tls_report(const TlsAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" THREAD LOCAL STORAGE (TLS) CALLBACK FORENSICS: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Modules with TLS Directory: " << report.modules_with_tls_count << L"\n";
    std::wcout << L"  Total Callbacks Inspected : " << report.total_callbacks_scanned << L"\n";
    std::wcout << L"  Anomalous Callbacks Found : " << report.anomalous_callbacks_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero anomalous TLS callbacks detected. All callbacks point to valid module code sections.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [" << (a.is_critical ? L"CRITICAL TLS HIJACK DETECTED" : L"TLS WARNING") << L"] "
                       << L"Module: " << a.module_name << L" (Base: " << to_hex_string(a.module_base) << L")\n";
            std::wcout << L"    Callback Address  : " << to_hex_string(a.callback_address) << L"\n";
            std::wcout << L"    Anomaly Type      : " << TlsAuditor::anomaly_type_to_string(a.type) << L"\n";
            std::wcout << L"    Memory Protection : " << a.protection_string << L"\n";
            std::wcout << L"    Details           : " << a.details << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_sections_report(const SectionAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" MAPPED SECTION VIEW & SHARED MEMORY FORENSICS: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Mapped Regions Inspected  : " << report.mapped_regions_count << L"\n";
    std::wcout << L"  Executable Mapped Sections: " << report.executable_sections_count << L"\n";
    std::wcout << L"  Anomalous Section Views   : " << report.anomalous_sections_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero section view anomalies detected. Normal memory mapping and backing file configuration.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [" << (a.is_critical ? L"CRITICAL SECTION ANOMALY" : L"SECTION WARNING") << L"] "
                       << L"Base Address: " << to_hex_string(a.base_address) << L"\n";
            std::wcout << L"    Anomaly Type      : " << SectionAuditor::anomaly_type_to_string(a.type) << L"\n";
            std::wcout << L"    Memory Protection : " << a.protection_string << L"\n";
            std::wcout << L"    Region Size       : 0x" << std::hex << a.region_size << std::dec << L" (" << format_bytes(a.region_size) << L")\n";
            if (!a.mapped_file.empty()) {
                std::wcout << L"    Backing Source    : " << a.mapped_file << L"\n";
            }
            std::wcout << L"    Details           : " << a.details << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_unwind_report(const UnwindAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" CALL STACK UNWIND & RUNTIME_FUNCTION FORENSICS: " << report.process_name << L" (PID " << report.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Threads Inspected         : " << report.threads_inspected << L"\n";
    std::wcout << L"  Stack Frames Evaluated    : " << report.frames_evaluated << L"\n";
    std::wcout << L"  Anomalous Frames Detected : " << report.anomalous_frames_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero unwind anomalies detected. All stack frame return addresses correlate to valid function metadata.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [STACK SPOOFING DETECTED] Thread TID: " << a.thread_id
                       << L" - Frame: " << to_hex_string(a.frame_address) << L"\n";
            std::wcout << L"    Anomaly Type      : " << UnwindAuditor::anomaly_type_to_string(a.type) << L"\n";
            if (!a.module_name.empty()) {
                std::wcout << L"    Module            : " << a.module_name << L"\n";
                std::wcout << L"    Module Base       : " << to_hex_string(a.module_base) << L"\n";
                std::wcout << L"    Module RVA        : +0x" << std::hex << a.rva << std::dec << L"\n";
            }
            std::wcout << L"    Details           : " << a.details << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_fiber_report(const FiberReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" FIBER EXECUTION CONTEXT & FIBER LOCAL STORAGE (FLS) FORENSICS (PID " << report.process_id << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Threads Inspected         : " << report.threads_examined << L"\n";
    std::wcout << L"  Fibers Identified         : " << report.fibers_detected << L"\n";
    std::wcout << L"  FLS Callbacks Inspected   : " << report.fls_callbacks_examined << L"\n";
    std::wcout << L"  Anomalous Fibers / FLS    : " << report.anomalies.size() << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero fiber anomalies detected. Fiber execution contexts and FLS callbacks resolve to clean modules.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [FIBER ANOMALY DETECTED] Target Address: " << to_hex_string(a.target_address) << L"\n";
            if (a.thread_id != 0) {
                std::wcout << L"    Thread TID        : " << a.thread_id << L"\n";
            }
            std::wcout << L"    Fiber Data Base   : " << to_hex_string(a.fiber_data_address) << L"\n";
            std::wcout << L"    Anomaly Type      : " << FiberAuditor::anomaly_type_to_string(a.anomaly_type) << L"\n";
            std::wcout << L"    Details           : " << a.anomaly_description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_clr_report(const ClrAuditReport& report) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" IN-MEMORY CLR & .NET INJECTION FORENSICS (PID " << report.process_id << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Compiled as Managed .NET  : " << (report.is_originally_managed ? L"YES (Managed PE)" : L"NO (Native Win32)") << L"\n";
    std::wcout << L"  CLR Runtime Loaded        : " << (report.has_clr_runtime ? report.clr_module_name : L"NONE") << L"\n";
    if (report.has_clr_runtime) {
        std::wcout << L"  CLR Module Base           : " << to_hex_string(report.clr_module_base) << L"\n";
    }
    std::wcout << L"  In-Memory .NET Assemblies : " << report.in_memory_assemblies_count << L"\n";
    std::wcout << L"  CLR Anomalies Detected    : " << report.anomalies.size() << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero CLR anomalies detected. Process does not exhibit unmanaged assembly injection or memory-loaded .NET artifacts.\n";
    } else {
        for (const auto& a : report.anomalies) {
            std::wcout << L"  [CLR INJECTION DETECTED] Address: " << to_hex_string(a.address) << L"\n";
            std::wcout << L"    Anomaly Type      : " << ClrAuditor::anomaly_type_to_string(a.anomaly_type) << L"\n";
            if (!a.clr_version.empty()) {
                std::wcout << L"    Metadata Version  : " << std::wstring(a.clr_version.begin(), a.clr_version.end()) << L"\n";
            }
            if (a.size > 0) {
                std::wcout << L"    Region Size       : 0x" << std::hex << a.size << std::dec << L" (" << format_bytes(a.size) << L")\n";
            }
            std::wcout << L"    Details           : " << a.description << L"\n\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

void Formatter::print_risk_assessment(const ProcessInfo& proc, const RiskScoreBreakdown& risk) {
    std::wcout << L"\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" FORENSIC RISK TRIAGE & THREAT VERDICT: " << proc.name << L" (PID " << proc.pid << L")\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Overall Risk Score        : " << risk.total_score << L" / 100\n";
    std::wcout << L"  Threat Verdict            : " << risk.verdict_string << L"\n";
    std::wcout << L"  Recommended Action        : " << risk.recommended_action << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (risk.risk_factors.empty()) {
        std::wcout << L"  Zero threat indicators identified. Process behavior matches clean baseline.\n";
    } else {
        std::wcout << L"  Identified Threat Factors:\n";
        for (const auto& f : risk.risk_factors) {
            std::wcout << L"    [*] " << f << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

std::string Formatter::to_json(
    const ProcessInfo& proc,
    const ProcessMemorySummary& summary,
    const std::vector<MemoryRegion>& regions,
    const ProcessInjectionReport& injection
) {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"process\": {\n";
    oss << "    \"pid\": " << proc.pid << ",\n";
    oss << "    \"parent_pid\": " << proc.parent_pid << ",\n";
    oss << "    \"is_64bit\": " << (proc.is_64bit ? "true" : "false") << ",\n";
    oss << "    \"is_elevated\": " << (proc.is_elevated ? "true" : "false") << "\n";
    oss << "  },\n";
    oss << "  \"summary\": {\n";
    oss << "    \"committed_bytes\": " << summary.total_committed_bytes << ",\n";
    oss << "    \"private_bytes\": " << summary.total_private_bytes << ",\n";
    oss << "    \"unbacked_executable_bytes\": " << summary.unbacked_executable_bytes << ",\n";
    oss << "    \"rwx_bytes\": " << summary.rwx_bytes << "\n";
    oss << "  },\n";
    oss << "  \"anomalies_count\": {\n";
    oss << "    \"critical\": " << injection.critical_anomalies_count << ",\n";
    oss << "    \"high\": " << injection.high_anomalies_count << ",\n";
    oss << "    \"medium\": " << injection.medium_anomalies_count << "\n";
    oss << "  },\n";
    oss << "  \"regions_count\": " << regions.size() << "\n";
    oss << "}\n";
    return oss.str();
}

std::string Formatter::to_csv(const std::vector<MemoryRegion>& regions) {
    std::ostringstream oss;
    oss << "BaseAddress,RegionSize,State,Type,Protect,IsExecutable,IsWritable,IsUnbacked,IsRWX\n";
    for (const auto& r : regions) {
        oss << "0x" << std::hex << r.base_address << std::dec << ","
            << r.region_size << ","
            << r.state << ","
            << r.type << ","
            << r.protect << ","
            << (r.is_executable ? 1 : 0) << ","
            << (r.is_writable ? 1 : 0) << ","
            << (r.is_unbacked_executable ? 1 : 0) << ","
            << (r.is_rwx ? 1 : 0) << "\n";
    }
    return oss.str();
}

} // namespace vmemscan
