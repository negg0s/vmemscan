#include "vmemscan/common.hpp"
#include "vmemscan/formatter.hpp"
#include "vmemscan/hook_detector.hpp"
#include "vmemscan/hollowing_detector.hpp"
#include "vmemscan/injection_detector.hpp"
#include "vmemscan/memory_dumper.hpp"
#include "vmemscan/memory_scanner.hpp"
#include "vmemscan/patch_detector.hpp"
#include "vmemscan/pattern_scanner.hpp"
#include "vmemscan/privileges.hpp"
#include "vmemscan/process_snapshot.hpp"
#include "vmemscan/snapshot_differ.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace vmemscan {

static std::string wide_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), result.data(), size, nullptr, nullptr);
    return result;
}

static void print_help() {
    Formatter::print_banner();
    std::wcout << L"Usage: vmemscan [options]\n\n";
    std::wcout << L"Target Selection:\n";
    std::wcout << L"  -p, --pid <PID>          Target process by Process ID\n";
    std::wcout << L"  -n, --name <pattern>     Target process by name or wildcard (e.g. notepad.exe, *chrome*)\n";
    std::wcout << L"  -l, --list               List running processes with architecture and memory usage\n";
    std::wcout << L"  --all                    Scan all running processes for code injection anomalies\n\n";
    std::wcout << L"Analysis Modes:\n";
    std::wcout << L"  -i, --injection          Audit target process for unbacked executable memory and injection\n";
    std::wcout << L"  -m, --map                Display virtual memory map of target process\n";
    std::wcout << L"  --hooks                  Audit inline API hooks in loaded system libraries\n";
    std::wcout << L"  --patches                Audit telemetry bypasses (ETW and AMSI in-memory patches)\n";
    std::wcout << L"  --hollowing              Audit process hollowing and PE entry point integrity\n";
    std::wcout << L"  --summary                Display virtual memory allocation statistics and breakdown\n\n";
    std::wcout << L"Memory Snapshot & Diffing:\n";
    std::wcout << L"  --save-snapshot <file>   Save process virtual memory snapshot baseline to JSON\n";
    std::wcout << L"  --diff-snapshot <file>   Compare current process memory against saved baseline\n\n";
    std::wcout << L"Memory Dumping & Carving:\n";
    std::wcout << L"  --dump <hex_addr>        Dump memory region starting at hexadecimal address\n";
    std::wcout << L"  --size <bytes>           Size in bytes to dump (default: region size)\n";
    std::wcout << L"  --out <path>             Destination path for dumped binary file\n";
    std::wcout << L"  --fixup-pe               Align section headers for dumped in-memory PE images\n\n";
    std::wcout << L"Memory Pattern Search:\n";
    std::wcout << L"  --pattern <hex_pattern>  Search hex pattern with wildcards (e.g. \"48 8B ?? ?? ?? E8\")\n";
    std::wcout << L"  --string <text>          Search ASCII string in process memory\n\n";
    std::wcout << L"Filters & Output:\n";
    std::wcout << L"  --only-unbacked          Filter memory map to unbacked executable memory only\n";
    std::wcout << L"  --only-rwx               Filter memory map to PAGE_EXECUTE_READWRITE only\n";
    std::wcout << L"  --limit <N>              Maximum rows to display in tables (default: 100)\n";
    std::wcout << L"  --json                   Export results in machine-readable JSON format\n";
    std::wcout << L"  --csv                    Export memory map in CSV format\n";
    std::wcout << L"  -h, --help               Display this help message\n";
    std::wcout << L"  -v, --version            Display version information\n\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"  vmemscan -p 1234 -i\n";
    std::wcout << L"  vmemscan -p 1234 --patches\n";
    std::wcout << L"  vmemscan -p 1234 --hollowing\n";
    std::wcout << L"  vmemscan -p 1234 --save-snapshot baseline.json\n";
    std::wcout << L"  vmemscan -p 1234 --diff-snapshot baseline.json\n";
    std::wcout << L"  vmemscan -p 1234 -m --only-unbacked\n";
    std::wcout << L"  vmemscan -p 1234 --dump 0x7FFA120000 --out payload.bin --fixup-pe\n";
    std::wcout << L"  vmemscan --all -i\n";
}

} // namespace vmemscan

int wmain(int argc, wchar_t* argv[]) {
    using namespace vmemscan;

    uint32_t target_pid = 0;
    std::wstring target_name;
    bool mode_list = false;
    bool mode_all = false;
    bool mode_map = false;
    bool mode_injection = false;
    bool mode_hooks = false;
    bool mode_patches = false;
    bool mode_hollowing = false;
    bool mode_summary = false;

    std::wstring save_snapshot_path;
    std::wstring diff_snapshot_path;

    bool mode_dump = false;
    uint64_t dump_addr = 0;
    uint64_t dump_size = 0;
    std::wstring dump_out_path;
    bool dump_fixup_pe = false;

    std::string pattern_hex;
    std::string pattern_str;

    MemoryFilter mem_filter{};
    size_t display_limit = 100;
    bool output_json = false;
    bool output_csv = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];

        if (arg == L"-h" || arg == L"--help") {
            print_help();
            return 0;
        } else if (arg == L"-v" || arg == L"--version") {
            std::wcout << L"vmemscan version 0.2.0\n";
            return 0;
        } else if (arg == L"-p" || arg == L"--pid") {
            if (i + 1 < argc) target_pid = static_cast<uint32_t>(_wtoi(argv[++i]));
        } else if (arg == L"-n" || arg == L"--name") {
            if (i + 1 < argc) target_name = argv[++i];
        } else if (arg == L"-l" || arg == L"--list") {
            mode_list = true;
        } else if (arg == L"--all") {
            mode_all = true;
        } else if (arg == L"-m" || arg == L"--map") {
            mode_map = true;
        } else if (arg == L"-i" || arg == L"--injection") {
            mode_injection = true;
        } else if (arg == L"--hooks") {
            mode_hooks = true;
        } else if (arg == L"--patches") {
            mode_patches = true;
        } else if (arg == L"--hollowing") {
            mode_hollowing = true;
        } else if (arg == L"--save-snapshot") {
            if (i + 1 < argc) save_snapshot_path = argv[++i];
        } else if (arg == L"--diff-snapshot") {
            if (i + 1 < argc) diff_snapshot_path = argv[++i];
        } else if (arg == L"--summary") {
            mode_summary = true;
        } else if (arg == L"--dump") {
            mode_dump = true;
            if (i + 1 < argc) dump_addr = _wcstoui64(argv[++i], nullptr, 0);
        } else if (arg == L"--size") {
            if (i + 1 < argc) dump_size = _wcstoui64(argv[++i], nullptr, 0);
        } else if (arg == L"--out") {
            if (i + 1 < argc) dump_out_path = argv[++i];
        } else if (arg == L"--fixup-pe") {
            dump_fixup_pe = true;
        } else if (arg == L"--pattern") {
            if (i + 1 < argc) {
                pattern_hex = wide_to_utf8(argv[++i]);
            }
        } else if (arg == L"--string") {
            if (i + 1 < argc) {
                pattern_str = wide_to_utf8(argv[++i]);
            }
        } else if (arg == L"--only-unbacked") {
            mem_filter.only_unbacked = true;
        } else if (arg == L"--only-rwx") {
            mem_filter.only_rwx = true;
        } else if (arg == L"--limit") {
            if (i + 1 < argc) display_limit = static_cast<size_t>(_wtoi(argv[++i]));
        } else if (arg == L"--json") {
            output_json = true;
        } else if (arg == L"--csv") {
            output_csv = true;
        }
    }

    PrivilegeManager::enable_debug_privilege();

    if (mode_list) {
        if (!output_json && !output_csv) Formatter::print_banner();
        auto processes = ProcessSnapshot::enumerate_processes();
        Formatter::print_process_list(processes);
        return 0;
    }

    if (mode_all) {
        if (!output_json && !output_csv) {
            Formatter::print_banner();
            std::wcout << L"Scanning all running processes for code injection anomalies...\n\n";
        }

        auto processes = ProcessSnapshot::enumerate_processes();
        size_t flagged_count = 0;

        for (const auto& proc : processes) {
            HANDLE hProc = ProcessSnapshot::open_process_for_inspection(proc.pid);
            if (!hProc) continue;

            auto regions_res = MemoryScanner::scan_process_memory(hProc);
            if (regions_res) {
                auto rep = InjectionDetector::analyze_process(hProc, proc, regions_res.value());
                if (rep.critical_anomalies_count > 0 || rep.high_anomalies_count > 0) {
                    ++flagged_count;
                    Formatter::print_injection_report(rep);
                }
            }
            CloseHandle(hProc);
        }

        if (flagged_count == 0) {
            std::wcout << L"All " << processes.size() << L" processes scanned. Zero injection anomalies detected.\n";
        }
        return 0;
    }

    // Single target process resolution
    ProcessInfo target_proc{};
    if (target_pid != 0) {
        auto p_res = ProcessSnapshot::get_process_by_pid(target_pid);
        if (!p_res) {
            std::wcerr << L"Error: " << p_res.error().to_string() << L"\n";
            return 1;
        }
        target_proc = p_res.value();
    } else if (!target_name.empty()) {
        ProcessFilter pf{};
        pf.name_pattern = target_name;
        auto matched = ProcessSnapshot::enumerate_processes(pf);
        if (matched.empty()) {
            std::wcerr << L"Error: No running process matched pattern: " << target_name << L"\n";
            return 1;
        }
        target_proc = matched.front();
    } else {
        print_help();
        return 0;
    }

    HANDLE hProcess = ProcessSnapshot::open_process_for_inspection(target_proc.pid);
    if (!hProcess) {
        std::wcerr << L"Failed to open process " << target_proc.pid << L" (" << target_proc.name << L"). Access denied.\n";
        std::wcerr << L"Try running from an elevated Administrator prompt.\n";
        return 1;
    }

    auto regions_res = MemoryScanner::scan_process_memory(hProcess, mem_filter);
    if (!regions_res) {
        std::wcerr << L"Failed to scan virtual memory: " << regions_res.error().to_string() << L"\n";
        CloseHandle(hProcess);
        return 1;
    }

    const auto& regions = regions_res.value();
    auto summary = MemoryScanner::compute_summary(target_proc.pid, target_proc.name, regions);

    if (mode_dump) {
        if (!output_json && !output_csv) Formatter::print_banner();
        if (dump_size == 0) {
            // Find region size
            for (const auto& r : regions) {
                if (dump_addr >= r.base_address && dump_addr < r.base_address + r.region_size) {
                    dump_size = r.region_size - (dump_addr - r.base_address);
                    break;
                }
            }
            if (dump_size == 0) dump_size = 4096;
        }

        auto dump_res = MemoryDumper::dump_region(hProcess, target_proc.pid, dump_addr, dump_size, dump_out_path, dump_fixup_pe);
        if (!dump_res) {
            std::wcerr << L"Dump failed: " << dump_res.error().to_string() << L"\n";
            CloseHandle(hProcess);
            return 1;
        }
        Formatter::print_dump_result(dump_res.value());
        CloseHandle(hProcess);
        return 0;
    }

    if (!pattern_hex.empty()) {
        if (!output_json && !output_csv) Formatter::print_banner();
        auto pb = PatternScanner::parse_hex_pattern(pattern_hex);
        auto matches = PatternScanner::scan_pattern(hProcess, regions, pb, display_limit);
        Formatter::print_pattern_matches(matches);
        CloseHandle(hProcess);
        return 0;
    }

    if (!pattern_str.empty()) {
        if (!output_json && !output_csv) Formatter::print_banner();
        auto matches = PatternScanner::scan_string(hProcess, regions, pattern_str, false, display_limit);
        Formatter::print_pattern_matches(matches);
        CloseHandle(hProcess);
        return 0;
    }

    if (mode_hooks) {
        if (!output_json && !output_csv) Formatter::print_banner();
        auto hook_rep = HookDetector::audit_process_hooks(hProcess, target_proc.pid, target_proc.name);
        Formatter::print_hook_report(hook_rep);
        CloseHandle(hProcess);
        return 0;
    }

    if (mode_patches) {
        if (!output_json && !output_csv) Formatter::print_banner();
        auto patch_rep = PatchDetector::audit_process_patches(hProcess, target_proc.pid, target_proc.name);
        Formatter::print_patch_report(patch_rep);
        CloseHandle(hProcess);
        return 0;
    }

    if (mode_hollowing) {
        if (!output_json && !output_csv) Formatter::print_banner();
        auto hollow_rep = HollowingDetector::analyze_process(hProcess, target_proc.pid, target_proc.name, target_proc.path, target_proc.is_64bit);
        Formatter::print_hollowing_report(hollow_rep);
        CloseHandle(hProcess);
        return 0;
    }

    if (!save_snapshot_path.empty()) {
        if (!output_json && !output_csv) Formatter::print_banner();
        auto snap = SnapshotDiffer::capture_snapshot(hProcess, target_proc.pid, target_proc.name, regions);
        auto save_res = SnapshotDiffer::save_snapshot_json(snap, save_snapshot_path);
        if (!save_res) {
            std::wcerr << L"Failed to save snapshot: " << save_res.error().to_string() << L"\n";
            CloseHandle(hProcess);
            return 1;
        }
        std::wcout << L"Memory snapshot successfully saved to: " << save_snapshot_path << L"\n";
        std::wcout << L"Captured " << snap.regions.size() << L" committed regions.\n";
        CloseHandle(hProcess);
        return 0;
    }

    if (!diff_snapshot_path.empty()) {
        if (!output_json && !output_csv) Formatter::print_banner();
        auto base_res = SnapshotDiffer::load_snapshot_json(diff_snapshot_path);
        if (!base_res) {
            std::wcerr << L"Failed to load baseline snapshot: " << base_res.error().to_string() << L"\n";
            CloseHandle(hProcess);
            return 1;
        }
        auto curr_snap = SnapshotDiffer::capture_snapshot(hProcess, target_proc.pid, target_proc.name, regions);
        auto diff_rep = SnapshotDiffer::compare_snapshots(base_res.value(), curr_snap);
        Formatter::print_diff_report(diff_rep);
        CloseHandle(hProcess);
        return 0;
    }

    if (output_json) {
        auto inj_rep = InjectionDetector::analyze_process(hProcess, target_proc, regions);
        std::cout << Formatter::to_json(target_proc, summary, regions, inj_rep);
        CloseHandle(hProcess);
        return 0;
    }

    if (output_csv) {
        std::cout << Formatter::to_csv(regions);
        CloseHandle(hProcess);
        return 0;
    }

    Formatter::print_banner();

    if (mode_map) {
        Formatter::print_memory_map(regions, display_limit);
    }

    if (mode_summary || (!mode_map && !mode_injection)) {
        Formatter::print_summary(summary);
    }

    if (mode_injection || (!mode_map && !mode_summary)) {
        auto inj_rep = InjectionDetector::analyze_process(hProcess, target_proc, regions);
        Formatter::print_injection_report(inj_rep);
    }

    CloseHandle(hProcess);
    return 0;
}
