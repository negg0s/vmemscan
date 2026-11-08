#include "vmemscan/c2_detector.hpp"

#include <algorithm>
#include <sstream>

namespace vmemscan {

static uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

bool C2Detector::parse_beacon_config(
    const uint8_t* raw_data,
    size_t size,
    uint8_t xor_key,
    uint64_t base_addr,
    C2BeaconArtifact& out_artifact
) {
    if (!raw_data || size < 64) {
        return false;
    }

    std::vector<uint8_t> dec(size);
    for (size_t i = 0; i < size; ++i) {
        dec[i] = static_cast<uint8_t>(raw_data[i] ^ xor_key);
    }

    // Look for setting ID 1 or 2
    size_t offset = 0;
    bool found_start = false;

    for (size_t i = 0; i + 8 < size; ++i) {
        uint16_t id = read_be16(&dec[i]);
        uint16_t type = read_be16(&dec[i + 2]);
        uint16_t len = read_be16(&dec[i + 4]);

        if (id == 1 && (type == 1 || type == 2) && len == 2) {
            offset = i;
            found_start = true;
            break;
        }
    }

    if (!found_start) {
        return false;
    }

    out_artifact.framework_name = L"Cobalt Strike Beacon";
    out_artifact.virtual_address = base_addr + offset;
    out_artifact.xor_key = xor_key;

    size_t cur = offset;
    size_t valid_entries = 0;

    while (cur + 6 <= size && valid_entries < 64) {
        uint16_t id = read_be16(&dec[cur]);
        uint16_t type = read_be16(&dec[cur + 2]);
        uint16_t len = read_be16(&dec[cur + 4]);

        if (id == 0 || cur + 6 + len > size) {
            break;
        }

        const uint8_t* val_ptr = &dec[cur + 6];
        C2ConfigEntry entry{};
        entry.setting_id = id;

        if (type == 1 && len == 2) {
            // Short
            entry.int_value = read_be16(val_ptr);
            entry.is_string = false;
        } else if (type == 2 && len == 4) {
            // Int
            entry.int_value = read_be32(val_ptr);
            entry.is_string = false;
        } else if (type == 3) {
            // String
            std::string s(reinterpret_cast<const char*>(val_ptr), (std::min)(static_cast<size_t>(len), static_cast<size_t>(256)));
            while (!s.empty() && s.back() == '\0') s.pop_back();
            entry.string_value.assign(s.begin(), s.end());
            entry.is_string = true;
        }

        switch (id) {
        case 2:
            entry.setting_name = L"Port";
            out_artifact.c2_port = static_cast<uint16_t>(entry.int_value);
            break;
        case 3:
            entry.setting_name = L"SleepTime";
            out_artifact.sleep_time_ms = entry.int_value;
            break;
        case 5:
            entry.setting_name = L"Jitter";
            out_artifact.jitter_percent = static_cast<uint16_t>(entry.int_value);
            break;
        case 8:
            entry.setting_name = L"C2Server";
            out_artifact.c2_server = entry.string_value;
            break;
        case 9:
            entry.setting_name = L"UserAgent";
            out_artifact.http_user_agent = entry.string_value;
            break;
        case 10:
            entry.setting_name = L"HttpPostUri";
            out_artifact.http_post_uri = entry.string_value;
            break;
        case 26:
            entry.setting_name = L"Watermark";
            out_artifact.watermark = entry.int_value;
            break;
        case 28:
            entry.setting_name = L"Spawnto";
            out_artifact.spawnto_process = entry.string_value;
            break;
        case 29:
            entry.setting_name = L"NamedPipe";
            out_artifact.named_pipe = entry.string_value;
            break;
        default:
            entry.setting_name = L"Setting_" + std::to_wstring(id);
            break;
        }

        out_artifact.raw_settings.push_back(std::move(entry));
        ++valid_entries;
        cur += 6 + len;
    }

    const bool has_c2_endpoint = !out_artifact.c2_server.empty() || !out_artifact.named_pipe.empty();
    return (valid_entries >= 4 && has_c2_endpoint);
}

C2ScanReport C2Detector::scan_process_c2(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    C2ScanReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess) {
        return rep;
    }

    const uint8_t candidate_keys[] = { 0x2E, 0x69, 0x00 };

    for (const auto& r : regions) {
        if (r.state != MEM_COMMIT || (r.type == MEM_IMAGE && (r.protect == PAGE_READONLY || r.protect == PAGE_EXECUTE_READ))) {
            continue;
        }

        ++rep.regions_scanned;

        // Sample up to 256 KB per region for C2 config tables
        const size_t sample_size = static_cast<size_t>((std::min)(r.region_size, static_cast<uint64_t>(262144)));
        std::vector<uint8_t> buffer(sample_size);
        SIZE_T read = 0;

        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(r.base_address), buffer.data(), sample_size, &read) || read < 128) {
            continue;
        }

        for (uint8_t key : candidate_keys) {
            C2BeaconArtifact artifact{};
            if (parse_beacon_config(buffer.data(), read, key, r.base_address, artifact)) {
                rep.detected_beacons.push_back(std::move(artifact));
                break;
            }
        }
    }

    return rep;
}

} // namespace vmemscan
