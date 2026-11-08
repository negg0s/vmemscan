#include "vmemscan/wiped_pe_detector.hpp"
#include "vmemscan/memory_scanner.hpp"

#include <algorithm>
#include <cstring>

namespace vmemscan {

std::vector<WipedPeAnomaly> WipedPeDetector::scan_region_for_wiped_pe(
    const uint8_t* buffer,
    size_t size,
    uint64_t region_base,
    uint32_t protect,
    uint32_t type
) {
    std::vector<WipedPeAnomaly> anomalies;
    if (!buffer || size < 512) {
        return anomalies;
    }

    // Only inspect private memory or unmapped regions (disk-backed MEM_IMAGE has normal valid headers)
    if (type != MEM_PRIVATE && type != MEM_MAPPED) {
        return anomalies;
    }

    // If MZ header is intact, this is a standard in-memory PE (handled by regular injection detector)
    if (buffer[0] == 'M' && buffer[1] == 'Z') {
        return anomalies;
    }

    // Search for PE\0\0 within the first 1024 bytes (or up to size - 256)
    const size_t max_search = std::min<size_t>(size - 256, 1024);

    for (size_t offset = 0; offset < max_search; offset += 4) {
        if (buffer[offset] == 'P' && buffer[offset + 1] == 'E' &&
            buffer[offset + 2] == '\0' && buffer[offset + 3] == '\0') {

            // Validate COFF File Header
            const size_t file_hdr_offset = offset + 4;
            if (file_hdr_offset + sizeof(IMAGE_FILE_HEADER) > size) {
                continue;
            }

            const auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(buffer + file_hdr_offset);

            // Check machine architecture
            bool valid_machine = (
                file_hdr->Machine == IMAGE_FILE_MACHINE_AMD64 ||
                file_hdr->Machine == IMAGE_FILE_MACHINE_I386 ||
                file_hdr->Machine == IMAGE_FILE_MACHINE_ARM64
            );
            if (!valid_machine) {
                continue;
            }

            // Check section count
            if (file_hdr->NumberOfSections == 0 || file_hdr->NumberOfSections > 96) {
                continue;
            }

            // Check SizeOfOptionalHeader
            if (file_hdr->SizeOfOptionalHeader < 0x60 || file_hdr->SizeOfOptionalHeader > 0x400) {
                continue;
            }

            // Check OptionalHeader magic
            const size_t opt_hdr_offset = file_hdr_offset + sizeof(IMAGE_FILE_HEADER);
            if (opt_hdr_offset + 2 > size) {
                continue;
            }

            uint16_t opt_magic = 0;
            std::memcpy(&opt_magic, buffer + opt_hdr_offset, sizeof(uint16_t));
            if (opt_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && opt_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                continue;
            }

            // Valid NT headers confirmed without MZ header
            WipedPeAnomaly a{};
            a.region_base = region_base;
            a.nt_headers_offset = static_cast<uint64_t>(offset);
            a.machine_architecture = file_hdr->Machine;
            a.section_count = file_hdr->NumberOfSections;
            a.current_protection = protect;
            a.protection_string = MemoryScanner::protect_to_string(protect);
            a.dos_header_wiped = true;

            // Check if section names are scrambled or erased
            const size_t sec_offset = opt_hdr_offset + file_hdr->SizeOfOptionalHeader;
            if (sec_offset + (file_hdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) <= size) {
                const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(buffer + sec_offset);
                for (WORD i = 0; i < file_hdr->NumberOfSections; ++i) {
                    bool non_printable = false;
                    for (int j = 0; j < 8; ++j) {
                        uint8_t c = sections[i].Name[j];
                        if (c != 0 && (c < 0x20 || c > 0x7E)) {
                            non_printable = true;
                            break;
                        }
                    }
                    if (non_printable) {
                        a.section_names_scrambled = true;
                        break;
                    }
                }
            }

            if (a.section_names_scrambled) {
                a.anomaly_description = L"Obfuscated PE: Valid NT headers with erased DOS header and scrambled section names";
            } else {
                a.anomaly_description = L"Wiped PE Header: Valid NT headers (PE\\0\\0) with erased DOS header (MZ magic missing)";
            }

            anomalies.push_back(std::move(a));
            break; // Stop after finding first valid NT header in region
        }
    }

    return anomalies;
}

WipedPeReport WipedPeDetector::audit_process_wiped_pe(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    WipedPeReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || pid == 0) {
        return rep;
    }

    for (const auto& r : regions) {
        // Inspect committed private or unmapped regions
        if (r.state != MEM_COMMIT || (r.type != MEM_PRIVATE && r.type != MEM_MAPPED)) {
            continue;
        }

        // Must be executable or writable
        if (!r.is_executable && !r.is_writable) {
            continue;
        }

        // Sample first 4096 bytes of region
        const size_t sample_size = std::min<size_t>(static_cast<size_t>(r.region_size), 4096);
        std::vector<uint8_t> buffer(sample_size);
        SIZE_T bytes_read = 0;

        if (ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(r.base_address),
            buffer.data(),
            sample_size,
            &bytes_read
        ) && bytes_read >= 512) {
            ++rep.regions_scanned;

            auto found = scan_region_for_wiped_pe(
                buffer.data(),
                bytes_read,
                r.base_address,
                r.protect,
                r.type
            );

            for (auto& a : found) {
                rep.anomalies.push_back(std::move(a));
            }
        }
    }

    rep.wiped_pe_count = rep.anomalies.size();
    return rep;
}

} // namespace vmemscan
