#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

enum class WorkingSetAnomalyType {
    CopiedImagePage,    // Executable MEM_IMAGE page modified via Copy-On-Write (Shared == 0)
    RwxImagePage        // Executable MEM_IMAGE page modified and marked PAGE_EXECUTE_READWRITE
};

struct WorkingSetAnomaly {
    uint64_t virtual_address = 0;
    std::wstring module_name;
    uint64_t module_base = 0;
    uint32_t rva = 0;
    WorkingSetAnomalyType anomaly_type = WorkingSetAnomalyType::CopiedImagePage;
    std::wstring details;
    DWORD memory_protection = 0;
    bool is_shared = false;
};

struct WorkingSetReport {
    uint32_t process_id = 0;
    std::wstring process_name;
    size_t image_pages_checked = 0;
    size_t valid_pages_in_ws = 0;
    size_t modified_cow_pages = 0;
    std::vector<WorkingSetAnomaly> anomalies;
};

class WorkingSetAuditor {
public:
    static WorkingSetReport audit_process_working_set(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name
    );
    static std::wstring anomaly_type_to_string(WorkingSetAnomalyType type);
};

} // namespace vmemscan
