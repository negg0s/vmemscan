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
