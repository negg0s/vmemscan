#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

enum class HollowingAnomalyType {
    None,
    UnmappedImageBase,       // ImageBase in PEB is MEM_PRIVATE instead of MEM_IMAGE
    EntryPointMismatch,      // AddressOfEntryPoint in memory != on disk
    EntryPointHooked,        // First instructions at EntryPoint are JMP/CALL/RET
    ImageSizeMismatch,       // SizeOfImage in memory != on disk
    HeadersCorrupted,        // DOS/NT headers corrupted or zeroed out (header wiping)
    SectionTampered          // Section characteristics modified from disk
};

struct HollowingAnomaly {
    HollowingAnomalyType type = HollowingAnomalyType::None;
    std::wstring description;
    uint64_t expected_value = 0;
    uint64_t actual_value = 0;
    std::vector<uint8_t> preview_bytes;
    bool is_critical = false;
};

struct HollowingReport {
    uint32_t pid = 0;
    std::wstring process_name;
    std::wstring image_path;
    uint64_t peb_address = 0;
    uint64_t in_memory_image_base = 0;
    uint64_t in_memory_entry_point = 0;
    uint64_t on_disk_entry_point = 0;
    bool is_hollowed = false;
    std::vector<HollowingAnomaly> anomalies;
};

class HollowingDetector {
public:
    static HollowingReport analyze_process(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::wstring& image_path,
        bool is_64bit
    );

    static std::wstring anomaly_type_to_string(HollowingAnomalyType type);
};

} // namespace vmemscan
