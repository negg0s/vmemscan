#include "vmemscan/ghosting_detector.hpp"
#include "vmemscan/nt_defs.hpp"

#include <vector>

namespace vmemscan {

GhostingReport GhostingDetector::audit_process_ghosting(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::wstring& image_path,
    uint64_t image_base,
    bool is_64bit
) {
    GhostingReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;
    rep.disk_path = image_path;

    if (!hProcess || image_path.empty()) {
        return rep;
    }

    if (image_base == 0) {
        auto pfnQuery = NtApiLoader::get_nt_query_information_process();
        if (pfnQuery) {
            PROCESS_BASIC_INFORMATION pbi{};
            ULONG ret_len = 0;
            if (pfnQuery(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len) == 0 && pbi.PebBaseAddress) {
                SIZE_T br = 0;
                ReadProcessMemory(
                    hProcess,
                    reinterpret_cast<const char*>(pbi.PebBaseAddress) + (is_64bit ? 0x10 : 0x08),
                    &image_base,
                    is_64bit ? sizeof(uint64_t) : sizeof(uint32_t),
                    &br
                );
            }
        }
    }

    // 1. Attempt to open backing file on disk
    HANDLE hFile = CreateFileW(
        image_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            rep.is_ghosted = true;
            GhostingAnomaly a{};
            a.anomaly_type = L"Process Ghosting (File Deleted On Disk)";
            a.disk_path = image_path;
            a.details = L"Process executable file does not exist on disk while process is actively running in memory.";
            a.is_critical = true;
            rep.anomalies.push_back(std::move(a));
            return rep;
        } else if (err == ERROR_SHARING_VIOLATION || err == ERROR_ACCESS_DENIED) {
            // Check if file is locked or in transactional state
            GhostingAnomaly a{};
            a.anomaly_type = L"Process Locking / Access Restriction";
            a.disk_path = image_path;
            a.details = L"Cannot open executable file with shared access flags (Error: " + std::to_wstring(err) + L").";
            a.is_critical = false;
            rep.anomalies.push_back(std::move(a));
        }
        return rep;
    }

    // 2. Check if file is in DeletePending state
    FILE_STANDARD_INFO std_info{};
    if (GetFileInformationByHandleEx(hFile, FileStandardInfo, &std_info, sizeof(std_info))) {
        if (std_info.DeletePending) {
            rep.is_ghosted = true;
            GhostingAnomaly a{};
            a.anomaly_type = L"Process Ghosting (DeletePending Flag Active)";
            a.disk_path = image_path;
            a.details = L"Executable file handle has DeletePending=TRUE. Binary was marked for deletion upon close.";
            a.is_critical = true;
            rep.anomalies.push_back(std::move(a));
        }
    }

    // 3. Compare disk file headers with in-memory image headers (Process Herpaderping / Doppelganging)
    if (image_base != 0) {
        DWORD bytes_read = 0;
        IMAGE_DOS_HEADER disk_dos{};
        if (ReadFile(hFile, &disk_dos, sizeof(disk_dos), &bytes_read, nullptr) && bytes_read == sizeof(disk_dos)) {
            if (disk_dos.e_magic != IMAGE_DOS_SIGNATURE) {
                rep.is_herpaderped = true;
                GhostingAnomaly a{};
                a.anomaly_type = L"Process Herpaderping (Disk File Overwritten With Non-PE Data)";
                a.disk_path = image_path;
                a.details = L"Disk executable file lacks valid DOS MZ header while in-memory image is executing.";
                a.is_critical = true;
                rep.anomalies.push_back(std::move(a));
            } else {
                // Seek to NT header on disk
                SetFilePointer(hFile, disk_dos.e_lfanew, nullptr, FILE_BEGIN);
                IMAGE_NT_HEADERS64 disk_nt{};
                if (ReadFile(hFile, &disk_nt, sizeof(disk_nt), &bytes_read, nullptr) && bytes_read == sizeof(disk_nt)) {
                    if (disk_nt.Signature != IMAGE_NT_SIGNATURE) {
                        rep.is_herpaderped = true;
                        GhostingAnomaly a{};
                        a.anomaly_type = L"Process Herpaderping (Corrupted NT Headers On Disk)";
                        a.disk_path = image_path;
                        a.details = L"Disk file NT header signature corrupted while memory holds valid executing image.";
                        a.is_critical = true;
                        rep.anomalies.push_back(std::move(a));
                    } else {
                        // Read memory headers
                        IMAGE_DOS_HEADER mem_dos{};
                        SIZE_T mem_read = 0;
                        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(image_base), &mem_dos, sizeof(mem_dos), &mem_read) &&
                            mem_dos.e_magic == IMAGE_DOS_SIGNATURE) {
                            IMAGE_NT_HEADERS64 mem_nt{};
                            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(image_base + mem_dos.e_lfanew), &mem_nt, sizeof(mem_nt), &mem_read) &&
                                mem_nt.Signature == IMAGE_NT_SIGNATURE) {

                                if (disk_nt.FileHeader.TimeDateStamp != mem_nt.FileHeader.TimeDateStamp) {
                                    GhostingAnomaly a{};
                                    a.anomaly_type = L"Process Image Tampering (TimeDateStamp Divergence)";
                                    a.disk_path = image_path;
                                    a.details = L"Compilation timestamp on disk (0x" + std::to_wstring(disk_nt.FileHeader.TimeDateStamp) +
                                                L") does not match in-memory timestamp (0x" + std::to_wstring(mem_nt.FileHeader.TimeDateStamp) + L").";
                                    a.is_critical = false;
                                    rep.anomalies.push_back(std::move(a));
                                }

                                if (disk_nt.OptionalHeader.AddressOfEntryPoint != mem_nt.OptionalHeader.AddressOfEntryPoint) {
                                    rep.is_herpaderped = true;
                                    GhostingAnomaly a{};
                                    a.anomaly_type = L"Process Herpaderping / Hollowing (EntryPoint Discrepancy)";
                                    a.disk_path = image_path;
                                    a.details = L"On-disk EntryPoint RVA (0x" + std::to_wstring(disk_nt.OptionalHeader.AddressOfEntryPoint) +
                                                L") does not match in-memory EntryPoint RVA (0x" + std::to_wstring(mem_nt.OptionalHeader.AddressOfEntryPoint) + L").";
                                    a.is_critical = true;
                                    rep.anomalies.push_back(std::move(a));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    CloseHandle(hFile);
    return rep;
}

} // namespace vmemscan
