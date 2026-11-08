#include "vmemscan/working_set_auditor.hpp"

#include <psapi.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace vmemscan {

std::wstring WorkingSetAuditor::anomaly_type_to_string(WorkingSetAnomalyType type) {
    switch (type) {
    case WorkingSetAnomalyType::CopiedImagePage:
        return L"Copy-On-Write Code Modification (Shared == 0 in MEM_IMAGE code section)";
    case WorkingSetAnomalyType::RwxImagePage:
        return L"RWX Permissions on Mapped Image Page (W^X breach)";
    default:
        return L"Unknown";
    }
}

static std::wstring extract_file_name(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos && pos + 1 < path.size()) {
        return path.substr(pos + 1);
    }
    return path;
}

WorkingSetReport WorkingSetAuditor::audit_process_working_set(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name
) {
    WorkingSetReport report{};
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

        // Only inspect committed executable image pages
        bool is_image = (mbi.Type == MEM_IMAGE);
        bool is_commit = (mbi.State == MEM_COMMIT);
        bool is_exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (is_image && is_commit && is_exec && mbi.RegionSize > 0) {
            wchar_t mapped_path[MAX_PATH]{0};
            std::wstring mod_name;
            if (GetMappedFileNameW(hProcess, mbi.BaseAddress, mapped_path, MAX_PATH) > 0) {
                mod_name = extract_file_name(mapped_path);
            }

            size_t page_count = mbi.RegionSize / 4096;
            if (page_count == 0) page_count = 1;
            if (page_count > 4096) page_count = 4096; // Cap batch size to 16MB per region

            std::vector<PSAPI_WORKING_SET_EX_INFORMATION> wsi(page_count);
            uint64_t base_int = reinterpret_cast<uint64_t>(mbi.BaseAddress);

            for (size_t i = 0; i < page_count; ++i) {
                wsi[i].VirtualAddress = reinterpret_cast<PVOID>(base_int + (i * 4096));
            }

            DWORD cb = static_cast<DWORD>(wsi.size() * sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
            if (K32QueryWorkingSetEx(hProcess, wsi.data(), cb)) {
                for (size_t i = 0; i < page_count; ++i) {
                    ++report.image_pages_checked;

                    // VirtualAttributes.Valid indicates page is resident in working set
                    if (wsi[i].VirtualAttributes.Valid) {
                        ++report.valid_pages_in_ws;

                        // VirtualAttributes.Shared: 1 = shared with system cache, 0 = private copy-on-write
                        bool is_shared = (wsi[i].VirtualAttributes.Shared != 0);

                        if (!is_shared) {
                            ++report.modified_cow_pages;

                            WorkingSetAnomaly anom{};
                            anom.virtual_address = base_int + (i * 4096);
                            anom.module_name = mod_name;
                            anom.module_base = reinterpret_cast<uint64_t>(mbi.AllocationBase);
                            anom.rva = static_cast<uint32_t>(anom.virtual_address - anom.module_base);
                            anom.memory_protection = mbi.Protect;
                            anom.is_shared = false;

                            if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
                                anom.anomaly_type = WorkingSetAnomalyType::RwxImagePage;
                                anom.details = L"Image code page modified and marked PAGE_EXECUTE_READWRITE (W^X breach)";
                            } else {
                                anom.anomaly_type = WorkingSetAnomalyType::CopiedImagePage;
                                anom.details = L"Image code page modified in-memory via Copy-On-Write (inline hook / patch indicator)";
                            }

                            report.anomalies.push_back(anom);
                        }
                    }
                }
            }
        }

        p += mbi.RegionSize;
    }

    return report;
}

} // namespace vmemscan
