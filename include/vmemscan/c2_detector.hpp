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

struct C2ConfigEntry {
    uint16_t setting_id = 0;
    std::wstring setting_name;
    std::wstring string_value;
    uint32_t int_value = 0;
    bool is_string = false;
};

struct C2BeaconArtifact {
    std::wstring framework_name; // e.g. "Cobalt Strike Beacon", "Generic Shellcode Stager"
    uint64_t virtual_address = 0;
    uint8_t xor_key = 0;
    std::wstring c2_server;
    uint16_t c2_port = 0;
    uint32_t sleep_time_ms = 0;
    uint16_t jitter_percent = 0;
    std::wstring http_user_agent;
    std::wstring http_post_uri;
    std::wstring spawnto_process;
    std::wstring named_pipe;
    uint32_t watermark = 0;
    std::vector<C2ConfigEntry> raw_settings;
};

struct C2ScanReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t regions_scanned = 0;
    std::vector<C2BeaconArtifact> detected_beacons;
};

class C2Detector {
public:
    static C2ScanReport scan_process_c2(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static bool parse_beacon_config(
        const uint8_t* data,
        size_t size,
        uint8_t xor_key,
        uint64_t base_addr,
        C2BeaconArtifact& out_artifact
    );
};

} // namespace vmemscan
