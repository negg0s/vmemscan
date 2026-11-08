#include "vmemscan/syscall_auditor.hpp"

#include <algorithm>

namespace vmemscan {

std::vector<SyscallStubFinding> SyscallAuditor::scan_buffer_for_syscalls(
    const uint8_t* data,
    size_t size,
    uint64_t base_address,
    bool is_unbacked,
    bool is_rwx,
    const std::wstring& mapped_module
) {
    std::vector<SyscallStubFinding> findings;
    if (!data || size < 2) {
        return findings;
    }

    // Look for 0x0F, 0x05 (SYSCALL opcode on x64)
    for (size_t i = 0; i + 1 < size; ++i) {
        if (data[i] == 0x0F && data[i + 1] == 0x05) {
            SyscallStubFinding finding{};
            finding.virtual_address = base_address + i;
            finding.is_unbacked = is_unbacked;
            finding.is_rwx = is_rwx;
            finding.mapped_module = mapped_module;

            // Check if preceded by classic MOV R10, RCX (4C 8B D1) and MOV EAX, imm32 (B8 xx xx 00 00)
            if (i >= 8 && data[i - 8] == 0x4C && data[i - 7] == 0x8B && data[i - 6] == 0xD1 && data[i - 5] == 0xB8) {
                finding.ssn = static_cast<uint32_t>(data[i - 4]) | (static_cast<uint32_t>(data[i - 3]) << 8);
                finding.stub_type = L"Direct Syscall Stub (Syswhispers / Hell's Gate)";

                size_t start = i - 8;
                size_t stub_len = (i + 2 < size && data[i + 2] == 0xC3) ? 11 : 10;
                finding.instruction_bytes.assign(&data[start], &data[start + stub_len]);
            } else if (i >= 5 && data[i - 5] == 0xB8) {
                finding.ssn = static_cast<uint32_t>(data[i - 4]) | (static_cast<uint32_t>(data[i - 3]) << 8);
                finding.stub_type = L"Direct Syscall Stub (MOV EAX, SSN; SYSCALL)";

                size_t start = i - 5;
                size_t stub_len = (i + 2 < size && data[i + 2] == 0xC3) ? 8 : 7;
                finding.instruction_bytes.assign(&data[start], &data[start + stub_len]);
            } else if (is_unbacked || is_rwx || (i + 2 < size && data[i + 2] == 0xC3)) {
                finding.stub_type = L"Raw Syscall Instruction";
                size_t preview_len = (std::min)(static_cast<size_t>(8), size - i);
                finding.instruction_bytes.assign(&data[i], &data[i + preview_len]);
            } else {
                continue;
            }

            findings.push_back(std::move(finding));
        }
    }

    return findings;
}

SyscallAuditReport SyscallAuditor::audit_process_syscalls(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    SyscallAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess) {
        return rep;
    }

    auto is_legitimate_syscall_module = [](const std::wstring& mod_path) -> bool {
        std::wstring p = mod_path;
        for (auto& c : p) c = static_cast<wchar_t>(towlower(c));
        return (p.find(L"ntdll.dll") != std::wstring::npos || p.find(L"win32u.dll") != std::wstring::npos);
    };

    for (const auto& r : regions) {
        if (!r.is_executable || r.state != MEM_COMMIT) {
            continue;
        }

        // Legitimate syscalls only reside in ntdll.dll and win32u.dll
        if (!r.mapped_file.empty() && is_legitimate_syscall_module(r.mapped_file)) {
            continue;
        }

        ++rep.regions_evaluated;

        // Sample up to 64 KB per region
        const size_t sample_size = static_cast<size_t>((std::min)(r.region_size, static_cast<uint64_t>(65536)));
        std::vector<uint8_t> buffer(sample_size);
        SIZE_T read = 0;

        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(r.base_address), buffer.data(), sample_size, &read) && read >= 2) {
            auto found = scan_buffer_for_syscalls(
                buffer.data(),
                read,
                r.base_address,
                r.is_unbacked_executable,
                r.is_rwx,
                r.mapped_file
            );

            for (auto& f : found) {
                rep.findings.push_back(std::move(f));
            }
        }
    }

    rep.anomalies_count = rep.findings.size();
    return rep;
}

} // namespace vmemscan
