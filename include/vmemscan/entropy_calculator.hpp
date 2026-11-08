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
#include <vector>

namespace vmemscan {

struct EntropyReport {
    uint64_t base_address = 0;
    uint64_t region_size = 0;
    double entropy = 0.0;
    bool is_executable = false;
    bool is_unbacked = false;
    bool is_high_entropy = false; // >= 7.20
    uint32_t protect = 0;
    std::wstring mapped_file;
};

class EntropyCalculator {
public:
    // Calculates Shannon entropy: -Sum(p_i * log2(p_i)) over byte distribution [0.0 - 8.0]
    static double calculate_entropy(const uint8_t* data, size_t size);

    // Audits virtual memory regions of a process for packed or encrypted code pages
    static std::vector<EntropyReport> audit_process_entropy(
        HANDLE hProcess,
        const std::vector<MemoryRegion>& regions,
        double threshold = 7.0
    );
};

} // namespace vmemscan
