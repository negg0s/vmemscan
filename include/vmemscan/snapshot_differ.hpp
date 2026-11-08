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

struct SnapshotRegion {
    uint64_t base_address = 0;
    uint64_t region_size = 0;
    uint32_t state = 0;
    uint32_t protect = 0;
    uint32_t type = 0;
    std::wstring mapped_file;
    bool is_executable = false;
    uint64_t content_hash = 0;
};

struct ProcessMemorySnapshot {
    uint32_t pid = 0;
    std::wstring process_name;
    uint64_t timestamp = 0;
    std::vector<SnapshotRegion> regions;
};

struct ProtectionEscalation {
    uint64_t base_address = 0;
    uint64_t region_size = 0;
    uint32_t old_protect = 0;
    uint32_t new_protect = 0;
    std::wstring mapped_file;
};

struct ModifiedCodeRegion {
    uint64_t base_address = 0;
    uint64_t region_size = 0;
    uint64_t old_hash = 0;
    uint64_t new_hash = 0;
    std::wstring mapped_file;
};

struct SnapshotDiffReport {
    uint32_t pid = 0;
    std::wstring process_name;
    std::vector<SnapshotRegion> new_executable_regions;
    std::vector<ProtectionEscalation> protection_escalations;
    std::vector<ModifiedCodeRegion> modified_code_regions;
    std::vector<SnapshotRegion> deallocated_regions;
};

class SnapshotDiffer {
public:
    static ProcessMemorySnapshot capture_snapshot(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static Result<bool> save_snapshot_json(
        const ProcessMemorySnapshot& snap,
        const std::wstring& out_path
    );

    static Result<ProcessMemorySnapshot> load_snapshot_json(
        const std::wstring& in_path
    );

    static SnapshotDiffReport compare_snapshots(
        const ProcessMemorySnapshot& baseline,
        const ProcessMemorySnapshot& current
    );
};

} // namespace vmemscan
