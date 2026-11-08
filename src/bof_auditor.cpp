#include "vmemscan/bof_auditor.hpp"

#include <psapi.h>
#include <algorithm>
#include <string_view>

namespace vmemscan {

std::wstring BofAuditor::anomaly_type_to_string(BofAnomalyType type) {
    switch (type) {
    case BofAnomalyType::BeaconApiArtifact:
        return L"Beacon API In-Memory Symbol Artifact (Cobalt Strike / Havoc BOF)";
    case BofAnomalyType::DynamicFunctionResolution:
        return L"Dynamic Function Resolution (DFR) Symbol Artifact (LIBRARY$Function)";
    case BofAnomalyType::CoffRelocationArtifact:
        return L"In-Memory COFF Object Relocation / Section Artifact";
    default:
        return L"Unknown";
    }
}

static const char* BEACON_API_SYMBOLS[] = {
    "BeaconDataParse",
    "BeaconDataInt",
    "BeaconDataShort",
    "BeaconDataLength",
    "BeaconDataExtract",
    "BeaconFormatAlloc",
    "BeaconFormatReset",
    "BeaconFormatFree",
    "BeaconFormatAppend",
    "BeaconFormatPrintf",
    "BeaconFormatToString",
    "BeaconFormatInt",
    "BeaconPrintf",
    "BeaconOutput",
    "BeaconUseToken",
    "BeaconRevertToken",
    "BeaconIsAdmin",
    "BeaconGetSpawnTo",
    "BeaconSpawnTemporaryProcess",
    "BeaconInjectProcess",
    "BeaconInjectTemporaryProcess",
    "BeaconCleanupProcess",
    "toWideChar"
};

static const char* DFR_LIBRARY_PREFIXES[] = {
    "KERNEL32$",
    "NTDLL$",
    "ADVAPI32$",
    "MSVCRT$",
    "USER32$",
    "WS2_32$",
    "OLE32$",
    "SHELL32$",
    "IPHLPAPI$",
    "SHLWAPI$",
    "NETAPI32$",
    "DNSAPI$",
    "SECUR32$",
    "CRYPT32$",
    "WININET$",
    "WINHTTP$"
};

BofReport BofAuditor::audit_process_bofs(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name
) {
    BofReport report{};
    report.process_id = pid;
    report.process_name = process_name;

    if (!hProcess || pid == 0) {
        return report;
    }

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);

    uint8_t* p = static_cast<uint8_t*>(si.lpMinimumApplicationAddress);
    uint8_t* max_addr = static_cast<uint8_t*>(si.lpMaximumApplicationAddress);

    while (p < max_addr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProcess, p, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            break;
        }

        // Only scan committed unbacked private or mapped memory
        bool is_unbacked = (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED);
        bool is_commit = (mbi.State == MEM_COMMIT);
        bool is_readable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
        bool is_guarded = (mbi.Protect & PAGE_GUARD) != 0;

        if (is_unbacked && is_commit && is_readable && !is_guarded && mbi.RegionSize >= 512) {
            ++report.unbacked_regions_scanned;

            size_t scan_size = mbi.RegionSize;
            if (scan_size > 2 * 1024 * 1024) {
                scan_size = 2 * 1024 * 1024; // Limit to 2MB per region for fast execution
            }

            std::vector<uint8_t> buffer(scan_size);
            SIZE_T read = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), scan_size, &read) && read >= 64) {
                std::string_view sv(reinterpret_cast<const char*>(buffer.data()), read);
                std::vector<std::string> matched_beacon;
                std::vector<std::string> matched_dfr;

                // 1. Scan for Beacon API symbols
                for (const char* sym : BEACON_API_SYMBOLS) {
                    if (sv.find(sym) != std::string_view::npos) {
                        matched_beacon.push_back(sym);
                    }
                }

                // 2. Scan for DFR library prefixes
                for (const char* pfx : DFR_LIBRARY_PREFIXES) {
                    size_t pos = sv.find(pfx);
                    if (pos != std::string_view::npos) {
                        // Extract symbol up to null terminator or non-printable character
                        size_t end = pos;
                        while (end < sv.size() && sv[end] >= 33 && sv[end] <= 126 && (end - pos) < 64) {
                            ++end;
                        }
                        if (end > pos) {
                            matched_dfr.push_back(std::string(sv.substr(pos, end - pos)));
                        }
                    }
                }

                if (!matched_beacon.empty() || !matched_dfr.empty()) {
                    ++report.bof_artifacts_found;

                    BofAnomaly anom{};
                    anom.virtual_address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                    anom.region_size = mbi.RegionSize;
                    anom.memory_protection = mbi.Protect;
                    anom.memory_type = mbi.Type;

                    for (const auto& s : matched_beacon) {
                        anom.matched_symbols.push_back(s);
                    }
                    for (const auto& s : matched_dfr) {
                        anom.matched_symbols.push_back(s);
                    }

                    if (!matched_beacon.empty()) {
                        anom.anomaly_type = BofAnomalyType::BeaconApiArtifact;
                        anom.details = L"Beacon Object File (BOF) internal API symbols discovered in unbacked memory";
                    } else {
                        anom.anomaly_type = BofAnomalyType::DynamicFunctionResolution;
                        anom.details = L"Dynamic Function Resolution (DFR) LIBRARY$Function symbols discovered in unbacked memory";
                    }

                    report.anomalies.push_back(anom);
                }
            }
        }

        p += mbi.RegionSize;
    }

    return report;
}

} // namespace vmemscan
