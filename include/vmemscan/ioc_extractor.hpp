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

enum class IocType {
    Url,
    NamedPipe,
    IpAddress,
    SystemCommand,
    FilePath,
    GenericString
};

struct IocArtifact {
    IocType type = IocType::GenericString;
    std::wstring value;
    uint64_t virtual_address = 0;
    bool is_unicode = false;
};

struct IocReport {
    uint32_t pid = 0;
    std::wstring process_name;
    uint64_t target_address = 0;
    size_t total_strings_found = 0;
    std::vector<IocArtifact> artifacts;
};

class IocExtractor {
public:
    static IocReport extract_iocs_from_memory(
        HANDLE hProcess,
        uint32_t pid,
        const std::wstring& process_name,
        uint64_t base_address,
        uint64_t size_to_scan,
        size_t min_len = 4
    );

    static std::vector<IocArtifact> scan_buffer_iocs(
        const uint8_t* data,
        size_t size,
        uint64_t base_address,
        size_t min_len = 4
    );

    static std::wstring ioc_type_to_string(IocType type);
};

} // namespace vmemscan
