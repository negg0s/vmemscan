#pragma once

#include "vmemscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

struct DumpResult {
    uint32_t pid{0};
    uint64_t base_address{0};
    uint64_t bytes_requested{0};
    uint64_t bytes_dumped{0};
    std::wstring output_path;
    bool is_pe_image{false};
    bool pe_reconstructed{false};
    uint64_t fnv1a_hash{0};
};

class MemoryDumper {
public:
    static Result<DumpResult> dump_region(
        HANDLE hProcess,
        uint32_t pid,
        uint64_t address,
        uint64_t size,
        const std::wstring& out_path = L"",
        bool fixup_pe = false
    );

    static uint64_t compute_fnv1a(const uint8_t* data, size_t size);
};

} // namespace vmemscan
