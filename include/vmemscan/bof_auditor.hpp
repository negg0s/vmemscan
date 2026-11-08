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

enum class BofAnomalyType {
    BeaconApiArtifact,              // Unbacked memory contains Cobalt Strike / Havoc Beacon API symbols
    DynamicFunctionResolution,      // Unbacked memory contains Dynamic Function Resolution (LIBRARY$Function) symbols
    CoffRelocationArtifact          // Unbacked memory contains COFF object file header or section table artifacts
};

struct BofAnomaly {
    uint64_t virtual_address = 0;
    size_t region_size = 0;
    BofAnomalyType anomaly_type = BofAnomalyType::BeaconApiArtifact;
    std::wstring details;
    std::vector<std::string> matched_symbols;
    DWORD memory_protection = 0;
    DWORD memory_type = 0;
};

struct BofReport {
    uint32_t process_id = 0;
    std::wstring process_name;
    size_t unbacked_regions_scanned = 0;
    size_t bof_artifacts_found = 0;
    std::vector<BofAnomaly> anomalies;
};

class BofAuditor {
public:
    static BofReport audit_process_bofs(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name
    );
    static std::wstring anomaly_type_to_string(BofAnomalyType type);
};

} // namespace vmemscan
