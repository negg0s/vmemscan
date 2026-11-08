#include "vmemscan/indirect_syscall_auditor.hpp"

#include <algorithm>

namespace vmemscan {

std::vector<IndirectSyscallFinding> IndirectSyscallAuditor::scan_buffer_for_indirect_syscalls(
    const uint8_t* data,
    size_t size,
    uint64_t base_address,
    bool is_unbacked,
    bool is_rwx,
    const std::wstring& mapped_module,
    const std::vector<MemoryRegion>& regions
) {
    std::vector<IndirectSyscallFinding> findings;
    if (!data || size < 10) {
        return findings;
    }

    auto find_region = [&](uint64_t addr) -> const MemoryRegion* {
        if (addr == 0) return nullptr;
        for (const auto& r : regions) {
            if (addr >= r.base_address && addr < r.base_address + r.region_size) {
                return &r;
            }
        }
        return nullptr;
    };

    auto is_syscall_target = [](const std::wstring& mod_path) -> bool {
        if (mod_path.empty()) return false;
        std::wstring p = mod_path;
        for (auto& c : p) c = static_cast<wchar_t>(towlower(c));
        return (p.find(L"ntdll.dll") != std::wstring::npos || p.find(L"win32u.dll") != std::wstring::npos);
    };

    for (size_t i = 0; i + 10 <= size; ++i) {
        // Pattern 1: 4C 8B D1 B8 xx xx 00 00 followed by E9 rel32
        if (i + 13 <= size &&
            data[i] == 0x4C && data[i + 1] == 0x8B && data[i + 2] == 0xD1 &&
            data[i + 3] == 0xB8 &&
            data[i + 6] == 0x00 && data[i + 7] == 0x00 &&
            data[i + 8] == 0xE9) {

            uint32_t ssn = static_cast<uint32_t>(data[i + 4]) | (static_cast<uint32_t>(data[i + 5]) << 8);
            int32_t rel32 = 0;
            memcpy(&rel32, &data[i + 9], sizeof(int32_t));

            uint64_t next_ip = base_address + i + 13;
            uint64_t target = next_ip + static_cast<int64_t>(rel32);

            const auto* tgt_reg = find_region(target);
            if (!tgt_reg || !is_syscall_target(tgt_reg->mapped_file)) {
                continue;
            }

            IndirectSyscallFinding f{};
            f.virtual_address = base_address + i;
            f.ssn = ssn;
            f.target_address = target;
            f.is_unbacked = is_unbacked;
            f.is_rwx = is_rwx;
            f.mapped_module = mapped_module;
            f.technique_name = L"Indirect Syscall Trampoline (Syswhispers3 / Hell's Hall)";
            f.instruction_bytes.assign(&data[i], &data[i + 13]);
            f.target_module = tgt_reg->mapped_file;

            findings.push_back(std::move(f));
            i += 12;
            continue;
        }

        // Pattern 2: B8 xx xx 00 00 followed by E9 rel32
        if (i + 10 <= size &&
            data[i] == 0xB8 &&
            data[i + 3] == 0x00 && data[i + 4] == 0x00 &&
            data[i + 5] == 0xE9) {

            uint32_t ssn = static_cast<uint32_t>(data[i + 1]) | (static_cast<uint32_t>(data[i + 2]) << 8);
            int32_t rel32 = 0;
            memcpy(&rel32, &data[i + 6], sizeof(int32_t));

            uint64_t next_ip = base_address + i + 10;
            uint64_t target = next_ip + static_cast<int64_t>(rel32);

            const auto* tgt_reg = find_region(target);
            if (!tgt_reg || !is_syscall_target(tgt_reg->mapped_file)) {
                continue;
            }

            IndirectSyscallFinding f{};
            f.virtual_address = base_address + i;
            f.ssn = ssn;
            f.target_address = target;
            f.is_unbacked = is_unbacked;
            f.is_rwx = is_rwx;
            f.mapped_module = mapped_module;
            f.technique_name = L"Indirect Syscall Trampoline (Tartarus' Gate)";
            f.instruction_bytes.assign(&data[i], &data[i + 10]);
            f.target_module = tgt_reg->mapped_file;

            findings.push_back(std::move(f));
            i += 9;
            continue;
        }
    }

    return findings;
}

IndirectSyscallReport IndirectSyscallAuditor::audit_process_indirect_syscalls(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    IndirectSyscallReport rep{};
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

        // Legitimate system libraries do not use external JMP stubs for syscalls
        if (!r.mapped_file.empty() && is_legitimate_syscall_module(r.mapped_file)) {
            continue;
        }

        ++rep.regions_evaluated;

        const size_t sample_size = static_cast<size_t>((std::min)(r.region_size, static_cast<uint64_t>(65536)));
        std::vector<uint8_t> buffer(sample_size);
        SIZE_T read = 0;

        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(r.base_address), buffer.data(), sample_size, &read) && read >= 10) {
            auto found = scan_buffer_for_indirect_syscalls(
                buffer.data(),
                read,
                r.base_address,
                r.is_unbacked_executable,
                r.is_rwx,
                r.mapped_file,
                regions
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
