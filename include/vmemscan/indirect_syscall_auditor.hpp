#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "vmemscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

struct IndirectSyscallFinding {
    uint64_t virtual_address = 0;
    uint32_t ssn = 0;
    uint64_t target_address = 0;
    bool is_unbacked = false;
    bool is_rwx = false;
    std::wstring mapped_module;
    std::wstring target_module;
    std::wstring technique_name;
    std::vector<uint8_t> instruction_bytes;
};

struct IndirectSyscallReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t regions_evaluated = 0;
    size_t anomalies_count = 0;
    std::vector<IndirectSyscallFinding> findings;
};

class IndirectSyscallAuditor {
public:
    static IndirectSyscallReport audit_process_indirect_syscalls(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::vector<IndirectSyscallFinding> scan_buffer_for_indirect_syscalls(
        const uint8_t* data,
        size_t size,
        uint64_t base_address,
        bool is_unbacked,
        bool is_rwx,
        const std::wstring& mapped_module,
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
