#include "vmemscan/c2_detector.hpp"
#include "vmemscan/common.hpp"
#include "vmemscan/entropy_calculator.hpp"
#include "vmemscan/formatter.hpp"
#include "vmemscan/hook_detector.hpp"
#include "vmemscan/hollowing_detector.hpp"
#include "vmemscan/injection_detector.hpp"
#include "vmemscan/ioc_extractor.hpp"
#include "vmemscan/memory_dumper.hpp"
#include "vmemscan/memory_scanner.hpp"
#include "vmemscan/module_auditor.hpp"
#include "vmemscan/patch_detector.hpp"
#include "vmemscan/pattern_scanner.hpp"
#include "vmemscan/peb_auditor.hpp"
#include "vmemscan/privileges.hpp"
#include "vmemscan/process_snapshot.hpp"
#include "vmemscan/snapshot_differ.hpp"
#include "vmemscan/thread_analyzer.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using namespace vmemscan;

static void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "Assertion failed: " << message << std::endl;
        std::exit(1);
    }
}

void test_privileges_check() {
    bool elevated = PrivilegeManager::is_elevated_admin();
    (void)elevated;
    bool debug_ok = PrivilegeManager::enable_debug_privilege();
    (void)debug_ok;
    check(true, "privileges_check ran without crashing");
}

void test_wildcard_matching() {
    check(ProcessSnapshot::match_wildcard(L"*.exe", L"notepad.exe"), "*.exe matches notepad.exe");
    check(ProcessSnapshot::match_wildcard(L"*chrome*", L"googlechrome.exe"), "*chrome* matches googlechrome.exe");
    check(ProcessSnapshot::match_wildcard(L"svc*", L"svchost.exe"), "svc* matches svchost.exe");
    check(ProcessSnapshot::match_wildcard(L"calc.???", L"calc.exe"), "calc.??? matches calc.exe");
    check(!ProcessSnapshot::match_wildcard(L"explorer.exe", L"calc.exe"), "explorer.exe does not match calc.exe");
    check(!ProcessSnapshot::match_wildcard(L"*.dll", L"program.exe"), "*.dll does not match program.exe");
    check(ProcessSnapshot::match_wildcard(L"", L"anything.exe"), "empty pattern matches anything");
}

void test_size_formatting() {
    check(Formatter::format_bytes(500) == L"500 B", "format 500 B");
    check(Formatter::format_bytes(1024) == L"1.00 KB", "format 1 KB");
    check(Formatter::format_bytes(1048576) == L"1.00 MB", "format 1 MB");
    check(Formatter::format_bytes(1073741824) == L"1.00 GB", "format 1 GB");
}

void test_hex_formatting() {
    check(Formatter::to_hex_string(0x1234, 4) == L"0x1234", "hex 0x1234");
    std::vector<uint8_t> bytes = { 0x48, 0x8B, 0xC4, 0x90 };
    check(Formatter::bytes_to_hex_preview(bytes) == L"48 8B C4 90", "preview 48 8B C4 90");
}

void test_memory_protection_strings() {
    check(MemoryScanner::protect_to_string(PAGE_READONLY) == L"R--", "PAGE_READONLY is R--");
    check(MemoryScanner::protect_to_string(PAGE_READWRITE) == L"RW-", "PAGE_READWRITE is RW-");
    check(MemoryScanner::protect_to_string(PAGE_EXECUTE_READ) == L"R-X", "PAGE_EXECUTE_READ is R-X");
    check(MemoryScanner::protect_to_string(PAGE_EXECUTE_READWRITE) == L"RWX", "PAGE_EXECUTE_READWRITE is RWX");
    check(MemoryScanner::state_to_string(MEM_COMMIT) == L"COMMIT", "MEM_COMMIT string");
    check(MemoryScanner::state_to_string(MEM_RESERVE) == L"RESERVE", "MEM_RESERVE string");
    check(MemoryScanner::type_to_string(MEM_IMAGE) == L"IMAGE", "MEM_IMAGE string");
    check(MemoryScanner::type_to_string(MEM_PRIVATE) == L"PRIVATE", "MEM_PRIVATE string");
}

void test_memory_summary_computation() {
    std::vector<MemoryRegion> regions;

    MemoryRegion r1{};
    r1.state = MEM_COMMIT;
    r1.type = MEM_IMAGE;
    r1.protect = PAGE_EXECUTE_READ;
    r1.region_size = 65536;
    r1.is_executable = true;
    regions.push_back(r1);

    MemoryRegion r2{};
    r2.state = MEM_COMMIT;
    r2.type = MEM_PRIVATE;
    r2.protect = PAGE_READWRITE;
    r2.region_size = 32768;
    regions.push_back(r2);

    MemoryRegion r3{};
    r3.state = MEM_COMMIT;
    r3.type = MEM_PRIVATE;
    r3.protect = PAGE_EXECUTE_READWRITE;
    r3.region_size = 4096;
    r3.is_executable = true;
    r3.is_writable = true;
    r3.is_unbacked_executable = true;
    r3.is_rwx = true;
    regions.push_back(r3);

    auto summary = MemoryScanner::compute_summary(1234, L"test.exe", regions);
    check(summary.pid == 1234, "pid == 1234");
    check(summary.total_regions == 3, "total_regions == 3");
    check(summary.total_committed_bytes == 65536 + 32768 + 4096, "committed bytes match");
    check(summary.total_image_bytes == 65536, "image bytes match");
    check(summary.total_private_bytes == 32768 + 4096, "private bytes match");
    check(summary.unbacked_executable_bytes == 4096, "unbacked executable bytes match");
    check(summary.unbacked_executable_regions_count == 1, "unbacked count == 1");
    check(summary.rwx_regions_count == 1, "rwx count == 1");
}

void test_shellcode_prolog_detection() {
    uint8_t msf_prolog[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8 };
    check(InjectionDetector::detect_shellcode_prolog(msf_prolog, sizeof(msf_prolog)), "detect msf prolog");

    uint8_t call_pop[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 };
    check(InjectionDetector::detect_shellcode_prolog(call_pop, sizeof(call_pop)), "detect call/pop");

    uint8_t func_prolog[] = { 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83 };
    check(InjectionDetector::detect_shellcode_prolog(func_prolog, sizeof(func_prolog)), "detect func prolog");

    uint8_t zeroes[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
    check(!InjectionDetector::detect_shellcode_prolog(zeroes, sizeof(zeroes)), "zeroes not shellcode");
}

void test_hook_instruction_detection() {
    // 1. Rel32 JMP: E9 00 10 00 00
    uint8_t jmp_rel[] = { 0xE9, 0x00, 0x10, 0x00, 0x00 };
    std::wstring hook_type;
    uint64_t target_addr = 0;
    bool is_hook = HookDetector::is_hook_instruction(jmp_rel, sizeof(jmp_rel), hook_type, 0x7FFA0000, target_addr);
    check(is_hook, "E9 is Rel32 JMP hook");
    check(target_addr == 0x7FFA0000 + 5 + 0x1000, "target address calculated correctly");

    // 2. QWORD Indirect JMP: FF 25 00 00 00 00 [8 bytes target]
    uint8_t jmp_ind[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    uint64_t ind_target = 0x7FFA888899990000ULL;
    std::memcpy(jmp_ind + 6, &ind_target, sizeof(uint64_t));
    is_hook = HookDetector::is_hook_instruction(jmp_ind, sizeof(jmp_ind), hook_type, 0x7FFA0000, target_addr);
    check(is_hook, "FF 25 is QWORD Indirect JMP hook");
    check(target_addr == ind_target, "indirect target address matches");

    // 3. Normal clean syscall stub: 4C 8B D1 B8 18 00 00 00 (mov r10, rcx; mov eax, 18h)
    uint8_t clean_syscall[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00 };
    is_hook = HookDetector::is_hook_instruction(clean_syscall, sizeof(clean_syscall), hook_type, 0x7FFA0000, target_addr);
    check(!is_hook, "clean syscall stub is not a hook");
}

void test_hex_pattern_parsing() {
    std::string pattern_str = "48 8B ?? ?? ?? E8 00";
    auto pattern = PatternScanner::parse_hex_pattern(pattern_str);
    check(pattern.size() == 7, "pattern size == 7");
    check(pattern[0].byte == 0x48 && !pattern[0].is_wildcard, "byte 0 is 0x48");
    check(pattern[1].byte == 0x8B && !pattern[1].is_wildcard, "byte 1 is 0x8B");
    check(pattern[2].is_wildcard, "byte 2 is wildcard");
    check(pattern[3].is_wildcard, "byte 3 is wildcard");
    check(pattern[4].is_wildcard, "byte 4 is wildcard");
    check(pattern[5].byte == 0xE8 && !pattern[5].is_wildcard, "byte 5 is 0xE8");
    check(pattern[6].byte == 0x00 && !pattern[6].is_wildcard, "byte 6 is 0x00");
}

void test_fnv1a_hash() {
    std::vector<uint8_t> data1 = { 'M', 'Z', 0x90, 0x00, 0x03 };
    uint64_t hash1 = MemoryDumper::compute_fnv1a(data1.data(), data1.size());
    uint64_t hash2 = MemoryDumper::compute_fnv1a(data1.data(), data1.size());
    check(hash1 == hash2, "fnv1a is deterministic");
    check(hash1 != 0, "hash != 0");
}

void test_process_enumeration() {
    auto list = ProcessSnapshot::enumerate_processes();
    check(!list.empty(), "process list is not empty");

    uint32_t my_pid = GetCurrentProcessId();
    bool found_self = false;
    for (const auto& p : list) {
        if (p.pid == my_pid) {
            found_self = true;
            check(p.thread_count > 0, "thread_count > 0");
            break;
        }
    }
    check(found_self, "current process found in process snapshot");
}

void test_self_memory_scan() {
    HANDLE hSelf = GetCurrentProcess();
    auto regions_res = MemoryScanner::scan_process_memory(hSelf);
    check(regions_res.has_value(), "self memory scan succeeded");

    const auto& regions = regions_res.value();
    check(!regions.empty(), "self memory regions not empty");

    auto summary = MemoryScanner::compute_summary(GetCurrentProcessId(), L"vmemscan_tests.exe", regions);
    check(summary.total_committed_bytes > 0, "total_committed_bytes > 0");

    ProcessInfo pInfo{};
    pInfo.pid = GetCurrentProcessId();
    pInfo.name = L"vmemscan_tests.exe";
    auto inj_rep = InjectionDetector::analyze_process(hSelf, pInfo, regions);
    check(inj_rep.pid == pInfo.pid, "injection report generated for self");
}

void test_patch_detection_patterns() {
    std::wstring desc;

    // 1. Direct RET
    uint8_t ret_bytes[] = { 0xC3, 0x90, 0x90 };
    check(PatchDetector::classify_prologue(ret_bytes, sizeof(ret_bytes), desc) == PatchType::EarlyReturn, "detects early RET");

    // 2. Breakpoint INT 3
    uint8_t bp_bytes[] = { 0xCC, 0x90, 0x90 };
    check(PatchDetector::classify_prologue(bp_bytes, sizeof(bp_bytes), desc) == PatchType::Breakpoint, "detects breakpoint INT 3");

    // 3. XOR EAX, EAX; RET
    uint8_t zero_bytes[] = { 0x31, 0xC0, 0xC3 };
    check(PatchDetector::classify_prologue(zero_bytes, sizeof(zero_bytes), desc) == PatchType::ZeroReturn, "detects XOR EAX, EAX; RET");

    // 4. AMSI invalid arg bypass (B8 57 00 07 80 C3)
    uint8_t amsi_bytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    check(PatchDetector::classify_prologue(amsi_bytes, sizeof(amsi_bytes), desc) == PatchType::InvalidArgReturn, "detects AMSI E_INVALIDARG bypass");

    // 5. Unconditional JMP
    uint8_t jmp_bytes[] = { 0xE9, 0x10, 0x20, 0x30, 0x40 };
    check(PatchDetector::classify_prologue(jmp_bytes, sizeof(jmp_bytes), desc) == PatchType::UnconditionalJump, "detects JMP");

    // 6. Clean syscall stub
    uint8_t clean_stub[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00 };
    check(PatchDetector::classify_prologue(clean_stub, sizeof(clean_stub), desc) == PatchType::None, "clean stub classified as None");
}

void test_hollowing_anomaly_classification() {
    std::wstring s1 = HollowingDetector::anomaly_type_to_string(HollowingAnomalyType::UnmappedImageBase);
    check(!s1.empty(), "Hollowing anomaly string not empty");

    std::wstring s2 = HollowingDetector::anomaly_type_to_string(HollowingAnomalyType::EntryPointMismatch);
    check(!s2.empty(), "EntryPointMismatch string not empty");

    std::wstring s3 = HollowingDetector::anomaly_type_to_string(HollowingAnomalyType::EntryPointHooked);
    check(!s3.empty(), "EntryPointHooked string not empty");
}

void test_snapshot_diffing() {
    ProcessMemorySnapshot baseline{};
    baseline.pid = 1234;
    baseline.process_name = L"test.exe";
    baseline.timestamp = 1000;

    SnapshotRegion r1{};
    r1.base_address = 0x10000;
    r1.region_size = 4096;
    r1.protect = PAGE_READONLY;
    r1.is_executable = false;
    r1.content_hash = 1111;
    baseline.regions.push_back(r1);

    SnapshotRegion r2{};
    r2.base_address = 0x20000;
    r2.region_size = 8192;
    r2.protect = PAGE_EXECUTE_READ;
    r2.is_executable = true;
    r2.content_hash = 2222;
    baseline.regions.push_back(r2);

    ProcessMemorySnapshot current = baseline;
    // 1. Escalate r1 protection
    current.regions[0].protect = PAGE_EXECUTE_READWRITE;
    current.regions[0].is_executable = true;

    // 2. Modify r2 content hash
    current.regions[1].content_hash = 3333;

    // 3. Add new executable region
    SnapshotRegion r3{};
    r3.base_address = 0x30000;
    r3.region_size = 4096;
    r3.protect = PAGE_EXECUTE_READWRITE;
    r3.is_executable = true;
    r3.content_hash = 4444;
    current.regions.push_back(r3);

    auto diff = SnapshotDiffer::compare_snapshots(baseline, current);
    check(diff.protection_escalations.size() == 1, "detected 1 protection escalation");
    check(diff.modified_code_regions.size() == 1, "detected 1 modified code region");
    check(diff.new_executable_regions.size() == 1, "detected 1 new executable region");
}

void test_shannon_entropy_calculation() {
    // 1. All zeros should have entropy 0.0
    std::vector<uint8_t> zeros(1024, 0);
    double e_zero = EntropyCalculator::calculate_entropy(zeros.data(), zeros.size());
    check(e_zero == 0.0, "zero buffer has 0.0 entropy");

    // 2. Uniform 256 bytes should have entropy 8.0
    std::vector<uint8_t> uniform(256);
    for (size_t i = 0; i < 256; ++i) {
        uniform[i] = static_cast<uint8_t>(i);
    }
    double e_uniform = EntropyCalculator::calculate_entropy(uniform.data(), uniform.size());
    check(std::abs(e_uniform - 8.0) < 0.001, "uniform distribution has 8.0 entropy");

    // 3. Repeating pattern has low entropy
    std::vector<uint8_t> repeating(1024);
    for (size_t i = 0; i < 1024; ++i) {
        repeating[i] = static_cast<uint8_t>(i % 2);
    }
    double e_rep = EntropyCalculator::calculate_entropy(repeating.data(), repeating.size());
    check(std::abs(e_rep - 1.0) < 0.001, "2-state repeating pattern has 1.0 entropy");
}

void test_thread_anomaly_strings() {
    std::wstring s1 = ThreadAnalyzer::anomaly_to_string(ThreadAnomalyType::UnbackedStartAddress);
    check(!s1.empty(), "UnbackedStartAddress string not empty");

    std::wstring s2 = ThreadAnalyzer::anomaly_to_string(ThreadAnomalyType::UnbackedInstructionPointer);
    check(!s2.empty(), "UnbackedInstructionPointer string not empty");

    std::wstring s3 = ThreadAnalyzer::anomaly_to_string(ThreadAnomalyType::RwxExecution);
    check(!s3.empty(), "RwxExecution string not empty");
}

void test_module_anomaly_strings() {
    std::wstring s1 = ModuleAuditor::anomaly_to_string(ModuleAnomalyType::UnlinkedFromPeb);
    check(!s1.empty(), "UnlinkedFromPeb string not empty");

    std::wstring s2 = ModuleAuditor::anomaly_to_string(ModuleAnomalyType::SuspiciousPath);
    check(!s2.empty(), "SuspiciousPath string not empty");
}

void test_c2_beacon_config_parser() {
    // Construct synthetic Cobalt Strike beacon config block
    std::vector<uint8_t> block;

    auto append_be16 = [&](uint16_t v) {
        block.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        block.push_back(static_cast<uint8_t>(v & 0xFF));
    };

    auto append_be32 = [&](uint32_t v) {
        block.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        block.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        block.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        block.push_back(static_cast<uint8_t>(v & 0xFF));
    };

    // Setting 1: BeaconType (1 = HTTP, len 2, type 1)
    append_be16(1); append_be16(1); append_be16(2); append_be16(1);
    // Setting 2: Port (len 2, type 1)
    append_be16(2); append_be16(1); append_be16(2); append_be16(443);
    // Setting 3: SleepTime (len 4, type 2)
    append_be16(3); append_be16(2); append_be16(4); append_be32(5000);
    // Setting 8: C2Server (len 15, type 3)
    std::string srv = "evil.c2-lab.com";
    append_be16(8); append_be16(3); append_be16(static_cast<uint16_t>(srv.size()));
    for (char c : srv) block.push_back(static_cast<uint8_t>(c));

    // Pad with zeros
    while (block.size() < 128) block.push_back(0);

    // XOR with key 0x2E
    const uint8_t key = 0x2E;
    for (size_t i = 0; i < block.size(); ++i) {
        block[i] ^= key;
    }

    C2BeaconArtifact art{};
    bool parsed = C2Detector::parse_beacon_config(block.data(), block.size(), key, 0x10000, art);
    check(parsed, "synthetic beacon config successfully parsed");
    check(art.c2_port == 443, "parsed beacon port == 443");
    check(art.sleep_time_ms == 5000, "parsed sleep time == 5000");
    check(art.c2_server == L"evil.c2-lab.com", "parsed C2 server matches");
}

void test_peb_anomaly_strings() {
    std::wstring s1 = PebAuditor::anomaly_to_string(PebAnomalyType::ImagePathSpoofing);
    check(!s1.empty(), "ImagePathSpoofing string not empty");

    std::wstring s2 = PebAuditor::anomaly_to_string(PebAnomalyType::DotNetProfilingHijack);
    check(!s2.empty(), "DotNetProfilingHijack string not empty");
}

void test_ioc_extractor_classification() {
    std::string sample = "Padding https://malicious-c2.example/endpoint.php and \\\\.\\pipe\\testpipe and 192.168.1.50 and powershell.exe -enc";
    std::vector<uint8_t> data(sample.begin(), sample.end());

    auto iocs = IocExtractor::scan_buffer_iocs(data.data(), data.size(), 0x20000, 4);
    check(!iocs.empty(), "IOCs extracted from buffer");

    bool has_url = false;
    bool has_pipe = false;
    bool has_ip = false;
    bool has_cmd = false;

    for (const auto& ioc : iocs) {
        if (ioc.type == IocType::Url) has_url = true;
        if (ioc.type == IocType::NamedPipe) has_pipe = true;
        if (ioc.type == IocType::IpAddress) has_ip = true;
        if (ioc.type == IocType::SystemCommand) has_cmd = true;
    }

    check(has_url, "detected URL IOC");
    check(has_pipe, "detected Named Pipe IOC");
    check(has_ip, "detected IPv4 IOC");
    check(has_cmd, "detected System Command IOC");
}

int main() {
    std::wcout << L"[RUN] test_privileges_check\n";
    test_privileges_check();

    std::wcout << L"[RUN] test_wildcard_matching\n";
    test_wildcard_matching();

    std::wcout << L"[RUN] test_size_formatting\n";
    test_size_formatting();

    std::wcout << L"[RUN] test_hex_formatting\n";
    test_hex_formatting();

    std::wcout << L"[RUN] test_memory_protection_strings\n";
    test_memory_protection_strings();

    std::wcout << L"[RUN] test_memory_summary_computation\n";
    test_memory_summary_computation();

    std::wcout << L"[RUN] test_shellcode_prolog_detection\n";
    test_shellcode_prolog_detection();

    std::wcout << L"[RUN] test_hook_instruction_detection\n";
    test_hook_instruction_detection();

    std::wcout << L"[RUN] test_hex_pattern_parsing\n";
    test_hex_pattern_parsing();

    std::wcout << L"[RUN] test_fnv1a_hash\n";
    test_fnv1a_hash();

    std::wcout << L"[RUN] test_process_enumeration\n";
    test_process_enumeration();

    std::wcout << L"[RUN] test_self_memory_scan\n";
    test_self_memory_scan();

    std::wcout << L"[RUN] test_patch_detection_patterns\n";
    test_patch_detection_patterns();

    std::wcout << L"[RUN] test_hollowing_anomaly_classification\n";
    test_hollowing_anomaly_classification();

    std::wcout << L"[RUN] test_snapshot_diffing\n";
    test_snapshot_diffing();

    std::wcout << L"[RUN] test_shannon_entropy_calculation\n";
    test_shannon_entropy_calculation();

    std::wcout << L"[RUN] test_thread_anomaly_strings\n";
    test_thread_anomaly_strings();

    std::wcout << L"[RUN] test_module_anomaly_strings\n";
    test_module_anomaly_strings();

    std::wcout << L"[RUN] test_c2_beacon_config_parser\n";
    test_c2_beacon_config_parser();

    std::wcout << L"[RUN] test_peb_anomaly_strings\n";
    test_peb_anomaly_strings();

    std::wcout << L"[RUN] test_ioc_extractor_classification\n";
    test_ioc_extractor_classification();

    std::wcout << L"All 21 unit test suites passed successfully.\n";
    return 0;
}
