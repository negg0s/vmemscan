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

enum class SectionAnomalyType {
    None,
    AnonymousExecutableSection,   // MEM_MAPPED executable with no file backing (shellcode section)
    DataFileExecutableSection,    // MEM_MAPPED executable backed by non-executable data file (.dat/.tmp/etc)
    RwxSection,                   // MEM_MAPPED with PAGE_EXECUTE_READWRITE
    SectionProtectionPromotion   // alloc_protect was non-exec, but protect elevated to executable
};

struct SectionAnomaly {
    uint64_t base_address = 0;
    uint64_t region_size = 0;
    uint32_t memory_protection = 0;
    std::wstring protection_string;
    std::wstring mapped_file;
    SectionAnomalyType type = SectionAnomalyType::None;
    bool is_critical = false;
    std::wstring details;
};

struct SectionAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t mapped_regions_count = 0;
    size_t executable_sections_count = 0;
    size_t anomalous_sections_count = 0;
    std::vector<SectionAnomaly> anomalies;
};

class SectionAuditor {
public:
    static SectionAuditReport audit_process_sections(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions
    );

    static std::wstring anomaly_type_to_string(SectionAnomalyType type);

    // Pure evaluation function for auditing and unit tests
    static std::vector<SectionAnomaly> evaluate_sections(
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
