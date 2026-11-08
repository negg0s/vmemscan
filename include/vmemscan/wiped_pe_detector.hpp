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

struct WipedPeAnomaly {
    uint64_t region_base = 0;
    uint64_t nt_headers_offset = 0;
    uint16_t machine_architecture = 0;
    uint16_t section_count = 0;
    uint32_t current_protection = 0;
    std::wstring protection_string;
    bool dos_header_wiped = false;
    bool section_names_scrambled = false;
    std::wstring anomaly_description;
};

struct WipedPeReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t regions_scanned = 0;
    size_t wiped_pe_count = 0;
    std::vector<WipedPeAnomaly> anomalies;
};

class WipedPeDetector {
public:
    static WipedPeReport audit_process_wiped_pe(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::vector<WipedPeAnomaly> scan_region_for_wiped_pe(
        const uint8_t* buffer,
        size_t size,
        uint64_t region_base,
        uint32_t protect,
        uint32_t type
    );
};

} // namespace vmemscan
