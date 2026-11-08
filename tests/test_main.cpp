#include "vmemscan/common.hpp"
#include "vmemscan/formatter.hpp"
#include "vmemscan/hook_detector.hpp"
#include "vmemscan/injection_detector.hpp"
#include "vmemscan/memory_dumper.hpp"
#include "vmemscan/memory_scanner.hpp"
#include "vmemscan/pattern_scanner.hpp"
#include "vmemscan/privileges.hpp"
#include "vmemscan/process_snapshot.hpp"

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

    std::wcout << L"All 12 unit test suites passed successfully.\n";
    return 0;
}
