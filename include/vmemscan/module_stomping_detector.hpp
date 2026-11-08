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

struct StompedModuleFinding {
    std::wstring module_name;
    std::wstring module_path;
    uint64_t module_base = 0;
    std::string section_name;
    uint64_t section_address = 0;
    size_t bytes_divergent = 0;
    std::wstring stomping_type;
    std::vector<uint8_t> in_memory_bytes;
    std::vector<uint8_t> on_disk_bytes;
};

struct ModuleStompingReport {
    uint32_t pid = 0;
    std::wstring process_name;
    size_t modules_evaluated = 0;
    size_t stomped_modules_count = 0;
    std::vector<StompedModuleFinding> findings;
};

class ModuleStompingDetector {
public:
    static ModuleStompingReport audit_process_module_stomping(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        bool is_64bit
    );

    static bool compare_section_prologue(
        const uint8_t* disk_bytes,
        const uint8_t* mem_bytes,
        size_t size,
        size_t& divergence_count
    );
};

} // namespace vmemscan
