#include "vmemscan/anti_debug_auditor.hpp"
#include "vmemscan/c2_detector.hpp"
#include "vmemscan/common.hpp"
#include "vmemscan/entropy_calculator.hpp"
#include "vmemscan/formatter.hpp"
#include "vmemscan/ghosting_detector.hpp"
#include "vmemscan/hook_detector.hpp"
#include "vmemscan/hollowing_detector.hpp"
#include "vmemscan/iat_hook_detector.hpp"
#include "vmemscan/indirect_syscall_auditor.hpp"
#include "vmemscan/injection_detector.hpp"
#include "vmemscan/ioc_extractor.hpp"
#include "vmemscan/ldr_auditor.hpp"
#include "vmemscan/memory_dumper.hpp"
#include "vmemscan/memory_scanner.hpp"
#include "vmemscan/mitigations_auditor.hpp"
#include "vmemscan/module_auditor.hpp"
#include "vmemscan/module_stomping_detector.hpp"
#include "vmemscan/patch_detector.hpp"
#include "vmemscan/pattern_scanner.hpp"
#include "vmemscan/peb_auditor.hpp"
#include "vmemscan/privileges.hpp"
#include "vmemscan/process_snapshot.hpp"
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

void test_direct_syscall_detection() {
    // 1. Classic Syswhispers stub: MOV R10, RCX; MOV EAX, 0x18; SYSCALL; RET
    // 4C 8B D1 B8 18 00 00 00 0F 05 C3
    const uint8_t syswhispers_stub[] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0x18, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3
    };

    auto findings1 = SyscallAuditor::scan_buffer_for_syscalls(
        syswhispers_stub, sizeof(syswhispers_stub), 0x140001000, true, false, L""
    );
    check(findings1.size() == 1, "detected direct syscall stub");
    check(findings1[0].ssn == 0x18, "extracted syscall SSN 0x18");
    check(findings1[0].stub_type.find(L"Syswhispers") != std::wstring::npos, "classified as Syswhispers stub");
    check(findings1[0].is_unbacked, "flagged as unbacked");

    // 2. Raw SYSCALL opcode
    const uint8_t raw_syscall[] = { 0x90, 0x90, 0x0F, 0x05, 0x90 };
    auto findings2 = SyscallAuditor::scan_buffer_for_syscalls(
        raw_syscall, sizeof(raw_syscall), 0x140002000, false, true, L"calc.exe"
    );
    check(findings2.size() == 1, "detected raw syscall opcode");
    check(findings2[0].stub_type.find(L"Raw Syscall") != std::wstring::npos, "classified as raw syscall opcode");
    check(findings2[0].is_rwx, "flagged as rwx");

    // 3. Clean buffer without syscall opcodes
    const uint8_t clean_buf[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0xC3 };
    auto findings3 = SyscallAuditor::scan_buffer_for_syscalls(
        clean_buf, sizeof(clean_buf), 0x140003000, false, false, L"user32.dll"
    );
    check(findings3.empty(), "clean buffer has zero direct syscalls");
}

void test_iat_hook_detection() {
    // Audit IAT of self process
    uint64_t image_base = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
    check(image_base != 0, "retrieved current module base");

    auto rep = IatHookDetector::audit_process_iat(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        L"vmemscan_tests.exe",
        sizeof(void*) == 8,
        {},
        image_base
    );

    check(rep.total_imports_checked > 0, "IAT audit traversed imported function descriptors");
    check(rep.hooked_imports_count == 0, "self process has zero hooked IAT entries");
}

void test_risk_scorer_evaluation() {
    // 1. Clean process baseline
    auto clean_risk = RiskScorer::compute_process_risk(false, false, 0, 0, 0, 0, 0, 0, 0, 0, false);
    check(clean_risk.total_score == 0, "clean baseline score is 0");
    check(clean_risk.verdict == ThreatVerdict::Clean, "clean baseline verdict is Clean");
    check(clean_risk.risk_factors.empty(), "clean baseline has no risk factors");

    // 2. High risk / compromised process
    auto crit_risk = RiskScorer::compute_process_risk(true, true, 2, 1, 1, 3, 2, 1, 1, 1, true);
    check(crit_risk.total_score == 100, "compromised process score capped at 100");
    check(crit_risk.verdict == ThreatVerdict::CriticalCompromised, "verdict is CriticalCompromised");
    check(crit_risk.risk_factors.size() >= 5, "multiple risk factors registered");

    // 3. Suspicious process
    auto susp_risk = RiskScorer::compute_process_risk(false, false, 1, 0, 1, 0, 0, 0, 0, 0, false);
    check(susp_risk.total_score >= 46 && susp_risk.total_score <= 75, "score falls in suspicious range");
    check(susp_risk.verdict == ThreatVerdict::Suspicious, "verdict is Suspicious");

    // 4. String representations
    check(RiskScorer::verdict_to_string(ThreatVerdict::Clean) == L"CLEAN (Normal Baseline)", "clean verdict string");
    check(RiskScorer::verdict_to_string(ThreatVerdict::CriticalCompromised).find(L"CRITICAL") != std::wstring::npos, "critical verdict string");
}

void test_stack_auditor_scan() {
    std::vector<MemoryRegion> regions;
    // Region 0: unbacked executable
    MemoryRegion r0{};
    r0.base_address = 0x00007FF710000000;
    r0.region_size = 0x10000;
    r0.is_executable = true;
    r0.is_unbacked_executable = true;
    regions.push_back(r0);

    // Region 1: RWX
    MemoryRegion r1{};
    r1.base_address = 0x00007FF720000000;
    r1.region_size = 0x10000;
    r1.is_executable = true;
    r1.is_rwx = true;
    regions.push_back(r1);

    // Region 2: normal backed executable module
    MemoryRegion r2{};
    r2.base_address = 0x00007FF730000000;
    r2.region_size = 0x10000;
    r2.is_executable = true;
    r2.mapped_file = L"C:\\Windows\\System32\\kernel32.dll";
    regions.push_back(r2);

    uint64_t simulated_stack[4] = {
        0x00007FF710000500, // Points to unbacked exec
        0x00007FF720000200, // Points to RWX
        0x00007FF730000100, // Points to clean module
        0x0000000000000000  // Null
    };

    auto anomalies = StackAuditor::scan_stack_buffer(
        1234,
        reinterpret_cast<const uint8_t*>(simulated_stack),
        sizeof(simulated_stack),
        0x000000100000,
        regions
    );

    check(anomalies.size() == 2, "detected 2 stack frame anomalies");
    check(anomalies[0].is_unbacked, "first anomaly flagged as unbacked");
    check(anomalies[1].is_rwx, "second anomaly flagged as rwx");
}

void test_indirect_syscall_scan() {
    std::vector<MemoryRegion> regions;
    MemoryRegion ntdll{};
    ntdll.base_address = 0x00007FFE80000000;
    ntdll.region_size = 0x200000;
    ntdll.mapped_file = L"C:\\Windows\\System32\\ntdll.dll";
    ntdll.is_executable = true;
    regions.push_back(ntdll);

    // Pattern 1: 4C 8B D1 B8 26 00 00 00 E9 rel32
    int64_t target1 = 0x00007FFE80050000;
    int64_t ip1 = 0x00007FFE70001000 + 13;
    int32_t rel32_1 = static_cast<int32_t>(target1 - ip1);

    uint8_t buf1[16] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0x26, 0x00, 0x00, 0x00,
        0xE9, 0x00, 0x00, 0x00, 0x00,
        0x90, 0x90, 0x90
    };
    memcpy(&buf1[9], &rel32_1, sizeof(int32_t));

    auto findings1 = IndirectSyscallAuditor::scan_buffer_for_indirect_syscalls(
        buf1, sizeof(buf1), 0x00007FFE70001000, true, false, L"", regions
    );

    check(findings1.size() == 1, "detected Syswhispers3 indirect syscall trampoline");
    check(findings1[0].ssn == 0x26, "extracted SSN 0x26");
    check(findings1[0].target_address == static_cast<uint64_t>(target1), "matched jump target address");
    check(findings1[0].target_module.find(L"ntdll.dll") != std::wstring::npos, "resolved jump target to ntdll.dll");
}

void test_extended_risk_scorer() {
    auto risk = RiskScorer::compute_process_risk(
        false, false, 0, 0, 0, 0, 0, 0, 0, 0, false,
        1, // unbacked stack frame (+40)
        1, // indirect syscall (+35)
        true, // ghosting (+45)
        1 // stomping (+35)
    );
    check(risk.total_score == 100, "risk score capped at 100");
    check(risk.verdict == ThreatVerdict::CriticalCompromised, "verdict is CriticalCompromised");
    check(risk.risk_factors.size() == 4, "four risk factors recorded");
}

void test_ghosting_detector_self() {
    wchar_t self_path[MAX_PATH]{0};
    GetModuleFileNameW(nullptr, self_path, MAX_PATH);

    auto rep = GhostingDetector::audit_process_ghosting(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        L"vmemscan_tests.exe",
        self_path,
        reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr)),
        sizeof(void*) == 8
    );

    check(!rep.is_ghosted, "self binary is not ghosted");
    check(!rep.is_herpaderped, "self binary is not herpaderped");
    check(rep.anomalies.empty(), "self binary has zero ghosting anomalies");
}

void test_module_stomping_comparison() {
    // 1. Identical buffers
    uint8_t b1[32]{0};
    uint8_t b2[32]{0};
    for (int i = 0; i < 32; ++i) { b1[i] = static_cast<uint8_t>(i); b2[i] = static_cast<uint8_t>(i); }
    size_t div1 = 0;
    check(!ModuleStompingDetector::compare_section_prologue(b1, b2, 32, div1), "identical bytes not stomped");
    check(div1 == 0, "zero divergence count");

    // 2. Trampoline overwrite (first byte changed to JMP 0xE9)
    uint8_t b3[32]{0};
    b3[0] = 0xE9;
    size_t div2 = 0;
    check(ModuleStompingDetector::compare_section_prologue(b1, b3, 32, div2), "JMP overwrite flagged as stomped");

    // 3. Heavy divergence (>= 16 bytes altered)
    uint8_t b4[32]{0};
    for (int i = 0; i < 20; ++i) { b4[i] = 0x90; }
    size_t div3 = 0;
    check(ModuleStompingDetector::compare_section_prologue(b1, b4, 32, div3), "16+ byte divergence flagged as stomped");
    check(div3 >= 16, "divergence >= 16");
}

void test_module_stomping_self() {
    auto rep = ModuleStompingDetector::audit_process_module_stomping(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        L"vmemscan_tests.exe",
        sizeof(void*) == 8
    );

    check(rep.modules_evaluated > 0, "evaluated loaded modules in self process");
    check(rep.stomped_modules_count == 0, "clean self process has zero stomped modules");
}

void test_sleep_mask_detection_simulation() {
    std::vector<MemoryRegion> regions;

    MemoryRegion r_rw{};
    r_rw.base_address = 0x10000000;
    r_rw.region_size = 0x10000;
    r_rw.type = MEM_PRIVATE;
    r_rw.state = MEM_COMMIT;
    r_rw.alloc_protect = PAGE_EXECUTE_READWRITE;
    r_rw.protect = PAGE_READWRITE;
    r_rw.is_executable = false;
    regions.push_back(r_rw);

    MemoryRegion r_rx{};
    r_rx.base_address = 0x7FFF0000;
    r_rx.region_size = 0x10000;
    r_rx.type = MEM_IMAGE;
    r_rx.state = MEM_COMMIT;
    r_rx.alloc_protect = PAGE_EXECUTE_READ;
    r_rx.protect = PAGE_EXECUTE_READ;
    r_rx.is_executable = true;
    regions.push_back(r_rx);

    uint64_t stack_slots[3] = {
        0x7FFF0120, // Valid image executable
        0x10004500, // Demoted private RW memory (Sleep mask evasion)
        0x00000000  // Zero slot
    };

    auto anomalies = SleepMaskDetector::scan_stack_for_masked_pages(1001, stack_slots, 3, regions);
    check(anomalies.size() == 1, "detected exactly 1 sleep masked return address");
    check(anomalies[0].wait_return_address == 0x10004500, "correct wait return address flagged");
    check(anomalies[0].current_protection == PAGE_READWRITE, "correct protection flagged");
}

void test_anti_debug_auditor_self() {
    auto rep = AntiDebugAuditor::audit_process_anti_debug(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        L"vmemscan_tests.exe",
        sizeof(void*) == 8
    );

    check(rep.pid == GetCurrentProcessId(), "self pid matches in anti-debug audit");
    check(rep.process_name == L"vmemscan_tests.exe", "process name matches in anti-debug audit");
    check(!rep.hardware_breakpoints_present, "self process has no hardware breakpoints");
}

void test_v080_risk_scorer_evaluation() {
    auto risk = RiskScorer::compute_process_risk(
        false, // c2
        false, // hollowing
        0,     // direct syscalls
        0,     // unbacked threads
        0,     // security patches
        0,     // unbacked exec
        0,     // rwx
        0,     // iat hooks
        0,     // unlinked modules
        0,     // high entropy
        false, // args spoofing
        0,     // unbacked stack frames
        0,     // indirect syscalls
        false, // ghosting
        0,     // stomped modules
        1,     // sleep masked regions (+45)
        true   // anti-debug detected (+25)
    );

    check(risk.total_score >= 70, "sleep mask + anti-debug score >= 70");
    check(risk.verdict == ThreatVerdict::Suspicious || risk.verdict == ThreatVerdict::CriticalCompromised,
          "verdict is Suspicious or Critical");
    check(!risk.risk_factors.empty(), "risk factors list is populated");
}

void test_wiped_pe_synthetic() {
    std::vector<uint8_t> buf(1024, 0);

    // Erased DOS header: buffer[0] and buffer[1] are zero
    buf[0] = 0x00;
    buf[1] = 0x00;

    // PE signature at offset 0x80
    size_t pe_offset = 0x80;
    buf[pe_offset] = 'P';
    buf[pe_offset + 1] = 'E';
    buf[pe_offset + 2] = '\0';
    buf[pe_offset + 3] = '\0';

    // COFF File Header at pe_offset + 4
    IMAGE_FILE_HEADER file_hdr{};
    file_hdr.Machine = IMAGE_FILE_MACHINE_AMD64;
    file_hdr.NumberOfSections = 4;
    file_hdr.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    file_hdr.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;
    std::memcpy(&buf[pe_offset + 4], &file_hdr, sizeof(IMAGE_FILE_HEADER));

    // Optional Header Magic at pe_offset + 4 + sizeof(IMAGE_FILE_HEADER)
    uint16_t opt_magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    size_t opt_offset = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);
    std::memcpy(&buf[opt_offset], &opt_magic, sizeof(uint16_t));

    auto anomalies = WipedPeDetector::scan_region_for_wiped_pe(
        buf.data(), buf.size(), 0x140000000, PAGE_EXECUTE_READ, MEM_PRIVATE
    );

    check(anomalies.size() == 1, "detected exactly 1 wiped PE header in region");
    check(anomalies[0].region_base == 0x140000000, "correct region base flagged");
    check(anomalies[0].dos_header_wiped, "dos_header_wiped is true");
    check(anomalies[0].machine_architecture == IMAGE_FILE_MACHINE_AMD64, "machine is AMD64");
    check(anomalies[0].section_count == 4, "section count is 4");
}

void test_wiped_pe_intact_mz_ignored() {
    std::vector<uint8_t> buf(1024, 0);
    // Intact MZ header
    buf[0] = 'M';
    buf[1] = 'Z';

    size_t pe_offset = 0x80;
    buf[pe_offset] = 'P';
    buf[pe_offset + 1] = 'E';
    buf[pe_offset + 2] = '\0';
    buf[pe_offset + 3] = '\0';

    IMAGE_FILE_HEADER file_hdr{};
    file_hdr.Machine = IMAGE_FILE_MACHINE_AMD64;
    file_hdr.NumberOfSections = 2;
    file_hdr.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    file_hdr.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    std::memcpy(&buf[pe_offset + 4], &file_hdr, sizeof(IMAGE_FILE_HEADER));

    uint16_t opt_magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    std::memcpy(&buf[pe_offset + 4 + sizeof(IMAGE_FILE_HEADER)], &opt_magic, sizeof(uint16_t));

    auto anomalies = WipedPeDetector::scan_region_for_wiped_pe(
        buf.data(), buf.size(), 0x140000000, PAGE_EXECUTE_READ, MEM_PRIVATE
    );

    check(anomalies.empty(), "intact MZ header ignored by wiped PE scanner");
}

void test_mitigations_auditor_self() {
    auto rep = MitigationsAuditor::audit_process_mitigations(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        L"vmemscan_tests.exe"
    );

    check(rep.pid == GetCurrentProcessId(), "self pid matches in mitigations audit");
    check(rep.process_name == L"vmemscan_tests.exe", "process name matches in mitigations audit");
    check(!rep.policies.empty(), "successfully retrieved exploit mitigation policies");
}

void test_veh_auditor_guard_trap() {
    std::vector<MemoryRegion> regions;

    MemoryRegion r_guard{};
    r_guard.base_address = 0x7FFF1000;
    r_guard.region_size = 0x1000;
    r_guard.state = MEM_COMMIT;
    r_guard.type = MEM_PRIVATE;
    r_guard.protect = PAGE_EXECUTE_READ | PAGE_GUARD;
    r_guard.is_executable = true;
    r_guard.is_unbacked_executable = true;
    regions.push_back(r_guard);

    MemoryRegion r_normal{};
    r_normal.base_address = 0x7FFF2000;
    r_normal.region_size = 0x1000;
    r_normal.state = MEM_COMMIT;
    r_normal.type = MEM_IMAGE;
    r_normal.protect = PAGE_EXECUTE_READ;
    r_normal.is_executable = true;
    regions.push_back(r_normal);

    auto traps = VehAuditor::scan_regions_for_guard_traps(regions);
    check(traps.size() == 1, "detected exactly 1 PAGE_GUARD trap");
    check(traps[0].is_guard_page_trap, "is_guard_page_trap is true");
    check(traps[0].target_address == 0x7FFF1000, "correct target address for guard trap");
    check(traps[0].memory_protection == (PAGE_EXECUTE_READ | PAGE_GUARD), "correct memory protection flagged");
}

void test_thread_pool_worker_stack_simulation() {
    std::vector<MemoryRegion> regions;

    MemoryRegion r_ntdll{};
    r_ntdll.base_address = 0x7FFE0000;
    r_ntdll.region_size = 0x20000;
    r_ntdll.state = MEM_COMMIT;
    r_ntdll.type = MEM_IMAGE;
    r_ntdll.protect = PAGE_EXECUTE_READ;
    r_ntdll.is_executable = true;
    r_ntdll.mapped_file = L"C:\\Windows\\System32\\ntdll.dll";
    regions.push_back(r_ntdll);

    MemoryRegion r_rwx{};
    r_rwx.base_address = 0x14002000;
    r_rwx.region_size = 0x10000;
    r_rwx.state = MEM_COMMIT;
    r_rwx.type = MEM_PRIVATE;
    r_rwx.protect = PAGE_EXECUTE_READWRITE;
    r_rwx.is_executable = true;
    r_rwx.is_rwx = true;
    r_rwx.is_unbacked_executable = true;
    regions.push_back(r_rwx);

    uint64_t stack_slots[3] = {
        0x7FFE1050,  // Clean ntdll frame
        0x14002500,  // Injected RWX callback (PoolParty)
        0x00000000
    };

    auto anomalies = ThreadPoolAuditor::scan_worker_stack(
        6001, 0x7FFE1000, stack_slots, 3, regions
    );

    check(anomalies.size() == 1, "detected exactly 1 thread pool callback anomaly");
    check(anomalies[0].thread_id == 6001, "correct thread ID flagged");
    check(anomalies[0].callback_address == 0x14002500, "correct callback address flagged");
    check(anomalies[0].is_rwx, "callback is in RWX memory");
}

void test_thread_pool_auditor_self() {
    auto scan_res = MemoryScanner::scan_process_memory(GetCurrentProcess());
    check(scan_res.has_value(), "memory scan succeeded for thread pool audit");

    auto rep = ThreadPoolAuditor::audit_process_thread_pool(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        L"vmemscan_tests.exe",
        scan_res.value()
    );

    check(rep.pid == GetCurrentProcessId(), "self pid matches in thread pool audit");
    check(rep.process_name == L"vmemscan_tests.exe", "process name matches in thread pool audit");
    check(rep.pool_anomalies_count == 0, "clean self process has zero thread pool callback anomalies");
}

void test_ldr_auditor_unlinked_detection() {
    std::vector<LdrModuleEntry> peb_modules;
    LdrModuleEntry m1{};
    m1.dll_base = 0x7FFA0000;
    m1.entry_point = 0x7FFA1000;
    m1.size_of_image = 0x50000;
    m1.base_dll_name = L"ntdll.dll";
    m1.in_load_order = true;
    m1.in_memory_order = true;
    m1.in_init_order = true;
    peb_modules.push_back(m1);

    std::vector<MemoryRegion> regions;
    // Known legitimate module
    MemoryRegion r1{};
    r1.base_address = 0x7FFA0000;
    r1.allocation_base = 0x7FFA0000;
    r1.region_size = 0x50000;
    r1.type = MEM_IMAGE;
    r1.state = MEM_COMMIT;
    r1.mapped_file = L"C:\\Windows\\System32\\ntdll.dll";
    regions.push_back(r1);

    // Unlinked stealth module (mapped image without PEB entry)
    MemoryRegion r2{};
    r2.base_address = 0x7FFB50000;
    r2.allocation_base = 0x7FFB50000;
    r2.region_size = 0x30000;
    r2.type = MEM_IMAGE;
    r2.state = MEM_COMMIT;
    r2.protect = PAGE_EXECUTE_READ;
    r2.is_executable = true;
    r2.mapped_file = L"C:\\Temp\\stealth_payload.dll";
    regions.push_back(r2);

    auto anomalies = LdrAuditor::evaluate_discrepancies(peb_modules, regions);
    check(anomalies.size() == 1, "detected exactly 1 unlinked module anomaly");
    check(anomalies[0].type == LdrAnomalyType::UnlinkedModule, "anomaly classified as UnlinkedModule");
    check(anomalies[0].module_base == 0x7FFB50000, "correct unlinked module base reported");
    check(anomalies[0].is_critical, "unlinked module marked critical");
}

void test_ldr_auditor_phantom_entry() {
    std::vector<LdrModuleEntry> peb_modules;
    // Legitimate module
    LdrModuleEntry m1{};
    m1.dll_base = 0x7FFA0000;
    m1.base_dll_name = L"ntdll.dll";
    m1.in_load_order = true;
    m1.in_memory_order = true;
    peb_modules.push_back(m1);

    // Phantom entry: points to unmapped / free address
    LdrModuleEntry m2{};
    m2.dll_base = 0x14000000;
    m2.base_dll_name = L"phantom_hook.dll";
    m2.in_load_order = true;
    m2.in_memory_order = false; // also desynced
    peb_modules.push_back(m2);

    std::vector<MemoryRegion> regions;
    MemoryRegion r1{};
    r1.base_address = 0x7FFA0000;
    r1.allocation_base = 0x7FFA0000;
    r1.region_size = 0x50000;
    r1.type = MEM_IMAGE;
    r1.state = MEM_COMMIT;
    regions.push_back(r1);

    // Region at 0x14000000 is MEM_PRIVATE, not MEM_IMAGE
    MemoryRegion r2{};
    r2.base_address = 0x14000000;
    r2.allocation_base = 0x14000000;
    r2.region_size = 0x10000;
    r2.type = MEM_PRIVATE;
    r2.state = MEM_COMMIT;
    regions.push_back(r2);

    auto anomalies = LdrAuditor::evaluate_discrepancies(peb_modules, regions);
    check(anomalies.size() >= 1, "detected phantom / desync anomalies");
    bool found_phantom = false;
    for (const auto& a : anomalies) {
        if (a.type == LdrAnomalyType::PhantomEntry) {
            found_phantom = true;
            check(a.module_base == 0x14000000, "phantom module base matches");
        }
    }
    check(found_phantom, "phantom PEB entry detected successfully");
}

void test_tls_auditor_unbacked_callback() {
    uint64_t mod_base = 0x7FFA0000;
    uint64_t mod_size = 0x20000;

    std::vector<MemoryRegion> regions;
    MemoryRegion r_mod{};
    r_mod.base_address = mod_base;
    r_mod.region_size = mod_size;
    r_mod.type = MEM_IMAGE;
    r_mod.state = MEM_COMMIT;
    r_mod.protect = PAGE_EXECUTE_READ;
    regions.push_back(r_mod);

    // Injected private shellcode memory region
    MemoryRegion r_priv{};
    r_priv.base_address = 0x12000000;
    r_priv.region_size = 0x10000;
    r_priv.type = MEM_PRIVATE;
    r_priv.state = MEM_COMMIT;
    r_priv.protect = PAGE_EXECUTE_READWRITE;
    r_priv.is_rwx = true;
    regions.push_back(r_priv);

    // Callbacks: 1 clean inside module, 1 pointing to private shellcode
    std::vector<uint64_t> callbacks = {
        0x7FFA1050,  // Clean callback in module
        0x12000500   // Hijacked callback in private memory
    };

    auto anomalies = TlsAuditor::evaluate_tls_module(
        mod_base, mod_size, L"target.dll", callbacks, regions
    );

    check(anomalies.size() == 1, "detected exactly 1 TLS callback anomaly");
    check(anomalies[0].type == TlsAnomalyType::UnbackedCallback, "classified as UnbackedCallback");
    check(anomalies[0].callback_address == 0x12000500, "flagged hijacked callback address");
    check(anomalies[0].is_critical, "unbacked callback flagged as critical");
}

void test_tls_auditor_clean_module() {
    uint64_t mod_base = 0x7FFA0000;
    uint64_t mod_size = 0x20000;

    std::vector<MemoryRegion> regions;
    MemoryRegion r_mod{};
    r_mod.base_address = mod_base;
    r_mod.region_size = mod_size;
    r_mod.type = MEM_IMAGE;
    r_mod.state = MEM_COMMIT;
    r_mod.protect = PAGE_EXECUTE_READ;
    regions.push_back(r_mod);

    std::vector<uint64_t> callbacks = {
        0x7FFA1050,
        0x7FFA1200
    };

    auto anomalies = TlsAuditor::evaluate_tls_module(
        mod_base, mod_size, L"clean.dll", callbacks, regions
    );

    check(anomalies.empty(), "clean TLS callbacks produce zero anomalies");
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

    std::wcout << L"[RUN] test_direct_syscall_detection\n";
    test_direct_syscall_detection();

    std::wcout << L"[RUN] test_iat_hook_detection\n";
    test_iat_hook_detection();

    std::wcout << L"[RUN] test_risk_scorer_evaluation\n";
    test_risk_scorer_evaluation();

    std::wcout << L"[RUN] test_stack_auditor_scan\n";
    test_stack_auditor_scan();

    std::wcout << L"[RUN] test_indirect_syscall_scan\n";
    test_indirect_syscall_scan();

    std::wcout << L"[RUN] test_extended_risk_scorer\n";
    test_extended_risk_scorer();

    std::wcout << L"[RUN] test_ghosting_detector_self\n";
    test_ghosting_detector_self();

    std::wcout << L"[RUN] test_module_stomping_comparison\n";
    test_module_stomping_comparison();

    std::wcout << L"[RUN] test_module_stomping_self\n";
    test_module_stomping_self();

    std::wcout << L"[RUN] test_sleep_mask_detection_simulation\n";
    test_sleep_mask_detection_simulation();

    std::wcout << L"[RUN] test_anti_debug_auditor_self\n";
    test_anti_debug_auditor_self();

    std::wcout << L"[RUN] test_v080_risk_scorer_evaluation\n";
    test_v080_risk_scorer_evaluation();

    std::wcout << L"[RUN] test_wiped_pe_synthetic\n";
    test_wiped_pe_synthetic();

    std::wcout << L"[RUN] test_wiped_pe_intact_mz_ignored\n";
    test_wiped_pe_intact_mz_ignored();

    std::wcout << L"[RUN] test_mitigations_auditor_self\n";
    test_mitigations_auditor_self();

    std::wcout << L"[RUN] test_veh_auditor_guard_trap\n";
    test_veh_auditor_guard_trap();

    std::wcout << L"[RUN] test_thread_pool_worker_stack_simulation\n";
    test_thread_pool_worker_stack_simulation();

    std::wcout << L"[RUN] test_thread_pool_auditor_self\n";
    test_thread_pool_auditor_self();

    std::wcout << L"[RUN] test_ldr_auditor_unlinked_detection\n";
    test_ldr_auditor_unlinked_detection();

    std::wcout << L"[RUN] test_ldr_auditor_phantom_entry\n";
    test_ldr_auditor_phantom_entry();

    std::wcout << L"[RUN] test_tls_auditor_unbacked_callback\n";
    test_tls_auditor_unbacked_callback();

    std::wcout << L"[RUN] test_tls_auditor_clean_module\n";
    test_tls_auditor_clean_module();

    std::wcout << L"All 43 unit test suites passed successfully.\n";
    return 0;
}
