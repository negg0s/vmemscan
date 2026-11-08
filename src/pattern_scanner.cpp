#include "vmemscan/pattern_scanner.hpp"
#include "vmemscan/memory_scanner.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace vmemscan {

std::vector<PatternByte> PatternScanner::parse_hex_pattern(const std::string& hex_pattern) {
    std::vector<PatternByte> result;
    std::istringstream stream(hex_pattern);
    std::string token;

    while (stream >> token) {
        if (token == "?" || token == "??" || token == "*") {
            PatternByte pb{};
            pb.is_wildcard = true;
            result.push_back(pb);
        } else {
            char* end_ptr = nullptr;
            unsigned long val = std::strtoul(token.c_str(), &end_ptr, 16);
            if (end_ptr != token.c_str()) {
                PatternByte pb{};
                pb.byte = static_cast<uint8_t>(val & 0xFF);
                pb.is_wildcard = false;
                result.push_back(pb);
            }
        }
    }

    return result;
}

std::vector<PatternMatch> PatternScanner::scan_pattern(
    HANDLE hProcess,
    const std::vector<MemoryRegion>& regions,
    const std::vector<PatternByte>& pattern,
    size_t max_matches
) {
    std::vector<PatternMatch> matches;
    if (pattern.empty() || !hProcess) {
        return matches;
    }

    const size_t pat_len = pattern.size();
    const size_t chunk_size = 65536;
    std::vector<uint8_t> buffer(chunk_size);

    for (const auto& r : regions) {
        if (r.state != MEM_COMMIT || (r.protect & PAGE_NOACCESS) || (r.protect & PAGE_GUARD)) {
            continue;
        }

        uint64_t offset = 0;
        while (offset < r.region_size && matches.size() < max_matches) {
            const size_t to_read = static_cast<size_t>(std::min<uint64_t>(chunk_size, r.region_size - offset));
            SIZE_T bytes_read = 0;

            const BOOL ok = ReadProcessMemory(
                hProcess,
                reinterpret_cast<LPCVOID>(r.base_address + offset),
                buffer.data(),
                to_read,
                &bytes_read
            );

            if (!ok || bytes_read < pat_len) {
                break;
            }

            for (size_t i = 0; i + pat_len <= bytes_read && matches.size() < max_matches; ++i) {
                bool found = true;
                for (size_t p = 0; p < pat_len; ++p) {
                    if (!pattern[p].is_wildcard && buffer[i + p] != pattern[p].byte) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    PatternMatch m{};
                    m.address = r.base_address + offset + i;
                    m.region_base = r.base_address;
                    m.region_type = MemoryScanner::type_to_string(r.type);
                    m.region_protect = MemoryScanner::protect_to_string(r.protect);

                    const size_t preview_len = std::min<size_t>(16, bytes_read - i);
                    m.preview_bytes.assign(buffer.data() + i, buffer.data() + i + preview_len);
                    matches.push_back(std::move(m));
                }
            }

            if (to_read <= pat_len) break;
            offset += (to_read - pat_len + 1);
        }
    }

    return matches;
}

std::vector<PatternMatch> PatternScanner::scan_string(
    HANDLE hProcess,
    const std::vector<MemoryRegion>& regions,
    const std::string& ascii_text,
    bool case_sensitive,
    size_t max_matches
) {
    std::vector<PatternByte> pattern;
    pattern.reserve(ascii_text.size());

    for (char c : ascii_text) {
        PatternByte pb{};
        pb.byte = case_sensitive ? static_cast<uint8_t>(c) : static_cast<uint8_t>(std::tolower(static_cast<unsigned char>(c)));
        pb.is_wildcard = false;
        pattern.push_back(pb);
    }

    return scan_pattern(hProcess, regions, pattern, max_matches);
}

} // namespace vmemscan
