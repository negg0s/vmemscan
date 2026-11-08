#include "vmemscan/entropy_calculator.hpp"

#include <algorithm>
#include <cmath>

namespace vmemscan {

double EntropyCalculator::calculate_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return 0.0;
    }

    size_t freq[256]{0};
    for (size_t i = 0; i < size; ++i) {
        ++freq[data[i]];
    }

    double entropy = 0.0;
    const double total = static_cast<double>(size);

    for (size_t i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / total;
            entropy -= p * (std::log(p) / std::log(2.0));
        }
    }

    return entropy;
}

std::vector<EntropyReport> EntropyCalculator::audit_process_entropy(
    HANDLE hProcess,
    const std::vector<MemoryRegion>& regions,
    double threshold
) {
    std::vector<EntropyReport> reports;
    if (!hProcess) {
        return reports;
    }

    for (const auto& r : regions) {
        if (r.state != MEM_COMMIT) {
            continue;
        }

        // Sample up to 64 KB of data to calculate entropy quickly and accurately
        const size_t sample_size = static_cast<size_t>((std::min)(r.region_size, static_cast<uint64_t>(65536)));
        std::vector<uint8_t> buffer(sample_size);
        SIZE_T read = 0;

        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(r.base_address), buffer.data(), sample_size, &read) && read > 256) {
            double ent = calculate_entropy(buffer.data(), read);
            if (ent >= threshold || r.is_unbacked_executable) {
                EntropyReport rep{};
                rep.base_address = r.base_address;
                rep.region_size = r.region_size;
                rep.entropy = ent;
                rep.is_executable = r.is_executable;
                rep.is_unbacked = r.is_unbacked_executable;
                rep.is_high_entropy = (ent >= 7.20);
                rep.protect = r.protect;
                rep.mapped_file = r.mapped_file;
                reports.push_back(std::move(rep));
            }
        }
    }

    return reports;
}

} // namespace vmemscan
