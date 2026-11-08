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

enum class LdrAnomalyType {
    None,
    UnlinkedModule,       // MEM_IMAGE PE region missing from PEB InLoadOrderModuleList
    PhantomEntry,         // PEB LDR entry points to unmapped / free / private memory
    ListDesync,           // Module present in InLoadOrder but absent in InMemoryOrder or InInitializationOrder
    SpoofedPath           // FullDllName or BaseDllName does not match disk file or is suspicious
};

struct LdrAnomaly {
    LdrAnomalyType type = LdrAnomalyType::None;
    uint64_t module_base = 0;
    uint64_t size_of_image = 0;
    std::wstring module_name;
    std::wstring module_path;
    std::wstring anomaly_description;
    bool is_critical = false;
};

struct LdrModuleEntry {
    uint64_t dll_base = 0;
    uint64_t entry_point = 0;
    uint32_t size_of_image = 0;
    std::wstring full_dll_name;
    std::wstring base_dll_name;
    bool in_load_order = false;
    bool in_memory_order = false;
    bool in_init_order = false;
};

struct LdrAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t peb_modules_count = 0;
    size_t mapped_images_count = 0;
    size_t unlinked_count = 0;
    size_t phantom_count = 0;
    std::vector<LdrAnomaly> anomalies;
};

class LdrAuditor {
public:
    static LdrAuditReport audit_process_ldr(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        const std::vector<MemoryRegion>& regions,
        bool is_64bit
    );

    static std::wstring anomaly_type_to_string(LdrAnomalyType type);

    // Core evaluation method for auditing and unit tests
    static std::vector<LdrAnomaly> evaluate_discrepancies(
        const std::vector<LdrModuleEntry>& peb_modules,
        const std::vector<MemoryRegion>& regions
    );
};

} // namespace vmemscan
