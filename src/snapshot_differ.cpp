#include "vmemscan/snapshot_differ.hpp"
#include "vmemscan/memory_dumper.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace vmemscan {

ProcessMemorySnapshot SnapshotDiffer::capture_snapshot(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    ProcessMemorySnapshot snap{};
    snap.pid = pid;
    snap.process_name = process_name;
    snap.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    for (const auto& r : regions) {
        if (r.state != MEM_COMMIT) {
            continue;
        }

        SnapshotRegion sr{};
        sr.base_address = r.base_address;
        sr.region_size = r.region_size;
        sr.state = r.state;
        sr.protect = r.protect;
        sr.type = r.type;
        sr.mapped_file = r.mapped_file;
        sr.is_executable = r.is_executable;

        if (r.is_executable && hProcess) {
            // Hash first page (up to 4096 bytes)
            const size_t sample_size = static_cast<size_t>((std::min)(r.region_size, static_cast<uint64_t>(4096)));
            std::vector<uint8_t> buffer(sample_size);
            SIZE_T read = 0;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(r.base_address), buffer.data(), sample_size, &read) && read > 0) {
                sr.content_hash = MemoryDumper::compute_fnv1a(buffer.data(), read);
            }
        }

        snap.regions.push_back(std::move(sr));
    }

    return snap;
}

Result<bool> SnapshotDiffer::save_snapshot_json(
    const ProcessMemorySnapshot& snap,
    const std::wstring& out_path
) {
    std::ofstream out(out_path, std::ios::trunc);
    if (!out.is_open()) {
        return Error(ERROR_FILE_NOT_FOUND, L"Failed to create snapshot output file");
    }

    out << "{\n";
    out << "  \"pid\": " << snap.pid << ",\n";
    out << "  \"timestamp\": " << snap.timestamp << ",\n";
    out << "  \"regions\": [\n";

    for (size_t i = 0; i < snap.regions.size(); ++i) {
        const auto& r = snap.regions[i];
        out << "    {";
        out << "\"base\": " << r.base_address << ", ";
        out << "\"size\": " << r.region_size << ", ";
        out << "\"state\": " << r.state << ", ";
        out << "\"protect\": " << r.protect << ", ";
        out << "\"type\": " << r.type << ", ";
        out << "\"is_exec\": " << (r.is_executable ? 1 : 0) << ", ";
        out << "\"hash\": " << r.content_hash;
        out << "}" << (i + 1 < snap.regions.size() ? "," : "") << "\n";
    }

    out << "  ]\n";
    out << "}\n";

    return true;
}

Result<ProcessMemorySnapshot> SnapshotDiffer::load_snapshot_json(
    const std::wstring& in_path
) {
    std::ifstream in(in_path);
    if (!in.is_open()) {
        return Error(ERROR_FILE_NOT_FOUND, L"Failed to open snapshot input file");
    }

    ProcessMemorySnapshot snap{};
    std::string line;

    while (std::getline(in, line)) {
        if (line.find("\"pid\":") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                snap.pid = static_cast<uint32_t>(std::strtoul(line.c_str() + pos + 1, nullptr, 10));
            }
        } else if (line.find("\"timestamp\":") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                snap.timestamp = std::strtoull(line.c_str() + pos + 1, nullptr, 10);
            }
        } else if (line.find("\"base\":") != std::string::npos) {
            SnapshotRegion r{};
            auto get_val = [&](const std::string& key) -> uint64_t {
                auto p = line.find(key);
                if (p == std::string::npos) return 0;
                auto col = line.find(':', p);
                if (col == std::string::npos) return 0;
                return std::strtoull(line.c_str() + col + 1, nullptr, 10);
            };

            r.base_address = get_val("\"base\":");
            r.region_size = get_val("\"size\":");
            r.state = static_cast<uint32_t>(get_val("\"state\":"));
            r.protect = static_cast<uint32_t>(get_val("\"protect\":"));
            r.type = static_cast<uint32_t>(get_val("\"type\":"));
            r.is_executable = (get_val("\"is_exec\":") != 0);
            r.content_hash = get_val("\"hash\":");

            snap.regions.push_back(std::move(r));
        }
    }

    return snap;
}

SnapshotDiffReport SnapshotDiffer::compare_snapshots(
    const ProcessMemorySnapshot& baseline,
    const ProcessMemorySnapshot& current
) {
    SnapshotDiffReport rep{};
    rep.pid = current.pid;
    rep.process_name = current.process_name;

    std::unordered_map<uint64_t, const SnapshotRegion*> base_map;
    for (const auto& r : baseline.regions) {
        base_map[r.base_address] = &r;
    }

    std::unordered_map<uint64_t, const SnapshotRegion*> curr_map;
    for (const auto& r : current.regions) {
        curr_map[r.base_address] = &r;

        auto it = base_map.find(r.base_address);
        if (it == base_map.end()) {
            // New region
            if (r.is_executable) {
                rep.new_executable_regions.push_back(r);
            }
        } else {
            const auto* old_r = it->second;
            // Check protection escalation (e.g. non-exec -> exec)
            if (!old_r->is_executable && r.is_executable) {
                ProtectionEscalation pe{};
                pe.base_address = r.base_address;
                pe.region_size = r.region_size;
                pe.old_protect = old_r->protect;
                pe.new_protect = r.protect;
                pe.mapped_file = r.mapped_file;
                rep.protection_escalations.push_back(std::move(pe));
            } else if (old_r->is_executable && r.is_executable) {
                // Check if code was modified
                if (old_r->content_hash != 0 && r.content_hash != 0 && old_r->content_hash != r.content_hash) {
                    ModifiedCodeRegion mc{};
                    mc.base_address = r.base_address;
                    mc.region_size = r.region_size;
                    mc.old_hash = old_r->content_hash;
                    mc.new_hash = r.content_hash;
                    mc.mapped_file = r.mapped_file;
                    rep.modified_code_regions.push_back(std::move(mc));
                }
            }
        }
    }

    for (const auto& r : baseline.regions) {
        if (curr_map.find(r.base_address) == curr_map.end()) {
            if (r.is_executable) {
                rep.deallocated_regions.push_back(r);
            }
        }
    }

    return rep;
}

} // namespace vmemscan
