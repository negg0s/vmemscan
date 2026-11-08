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

enum class ModuleAnomalyType {
    None,
    UnlinkedFromPeb,       // Loaded executable image unlinked from PEB module list
    SuspiciousPath,        // Library loaded from temp, appdata, or public directory
    MismatchedPath         // PEB reported path differs from mapped memory path
};

struct LoadedModuleInfo {
    std::wstring module_name;
    std::wstring module_path;
    uint64_t base_address = 0;
    uint32_t size_of_image = 0;
    bool in_peb_list = false;
    bool in_toolhelp_list = false;
    std::vector<ModuleAnomalyType> anomalies;
};

struct ModuleAuditReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t total_modules = 0;
    size_t anomalous_modules_count = 0;
    std::vector<LoadedModuleInfo> modules;
};

class ModuleAuditor {
public:
    static ModuleAuditReport audit_process_modules(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        bool is_64bit
    );

    static std::wstring anomaly_to_string(ModuleAnomalyType type);
};

} // namespace vmemscan
