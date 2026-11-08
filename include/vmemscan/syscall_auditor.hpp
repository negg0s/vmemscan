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

struct SyscallStubFinding {
    uint64_t virtual_address = 0;
    uint32_t ssn = 0; // System Service Number (syscall ID)
    bool is_unbacked = false;
    bool is_rwx = false;
    std::wstring mapped_module;
    std::vector<uint8_t> instruction_bytes;
    std::wstring stub_type; // e.g. "Direct Syscall Stub (Syswhispers/Hell's Gate)", "Raw Syscall Opcode"
};

struct SyscallAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t regions_evaluated = 0;
    size_t anomalies_count = 0;
    std::vector<SyscallStubFinding> findings;
};

class SyscallAuditor {
public:
    static SyscallAuditReport audit_process_syscalls(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::vector<SyscallStubFinding> scan_buffer_for_syscalls(
        const uint8_t* data,
        size_t size,
        uint64_t base_address,
        bool is_unbacked,
        bool is_rwx,
        const std::wstring& mapped_module
    );
};

} // namespace vmemscan
