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

enum class ClrAnomalyType {
    UnmanagedProcessClrLoaded,  // Native Win32 process loaded CLR (execute-assembly / Donut injection)
    InMemoryDotNetAssembly,     // Private memory contains .NET metadata header (BSJB) without disk backing
    RwxJitHeap                  // CLR JIT-compiled code heap allocated with PAGE_EXECUTE_READWRITE
};

struct ClrAnomaly {
    uint64_t address = 0;
    size_t size = 0;
    ClrAnomalyType anomaly_type = ClrAnomalyType::UnmanagedProcessClrLoaded;
    std::wstring description;
    std::string clr_version;
    DWORD memory_protection = 0;
    DWORD memory_type = 0;
};

struct ClrAuditReport {
    uint32_t process_id = 0;
    bool is_originally_managed = false;
    bool has_clr_runtime = false;
    std::wstring clr_module_name;
    uint64_t clr_module_base = 0;
    size_t in_memory_assemblies_count = 0;
    std::vector<ClrAnomaly> anomalies;
};

class ClrAuditor {
public:
    static ClrAuditReport audit_process(HANDLE hProcess, uint32_t pid);
    static std::wstring anomaly_type_to_string(ClrAnomalyType type);
};

} // namespace vmemscan
