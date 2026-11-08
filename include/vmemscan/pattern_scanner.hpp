#pragma once

#include "vmemscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace vmemscan {

struct PatternMatch {
    uint64_t address{0};
    uint64_t region_base{0};
    std::wstring region_type;
    std::wstring region_protect;
    std::vector<uint8_t> preview_bytes;
    std::wstring matched_text;
};

struct PatternByte {
    uint8_t byte{0};
    bool is_wildcard{false};
};

class PatternScanner {
public:
    static std::vector<PatternByte> parse_hex_pattern(const std::string& hex_pattern);

    static std::vector<PatternMatch> scan_pattern(
        HANDLE hProcess,
        const std::vector<MemoryRegion>& regions,
        const std::vector<PatternByte>& pattern,
        size_t max_matches = 50
    );

    static std::vector<PatternMatch> scan_string(
        HANDLE hProcess,
        const std::vector<MemoryRegion>& regions,
        const std::string& ascii_text,
        bool case_sensitive = false,
        size_t max_matches = 50
    );
};

} // namespace vmemscan
