#include "vmemscan/hollowing_detector.hpp"
#include "vmemscan/nt_defs.hpp"

#include <vector>

namespace vmemscan {

std::wstring HollowingDetector::anomaly_type_to_string(HollowingAnomalyType type) {
    switch (type) {
    case HollowingAnomalyType::None:                    return L"None";
    case HollowingAnomalyType::UnmappedImageBase:       return L"Unmapped ImageBase (MEM_PRIVATE instead of MEM_IMAGE)";
    case HollowingAnomalyType::EntryPointMismatch:      return L"Entry Point Mismatch (Memory vs Disk)";
    case HollowingAnomalyType::EntryPointHooked:        return L"Entry Point Patched / Hooked (Inline Redirection)";
    case HollowingAnomalyType::ImageSizeMismatch:       return L"Image Size Mismatch (Memory vs Disk)";
    case HollowingAnomalyType::HeadersCorrupted:        return L"PE Headers Corrupted / Header Stomping";
    case HollowingAnomalyType::SectionTampered:         return L"Section Header Characteristics Mismatch";
    default:                                            return L"Unknown";
    }
}

HollowingReport HollowingDetector::analyze_process(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::wstring& image_path,
    bool is_64bit
) {
    HollowingReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;
    rep.image_path = image_path;

    if (!hProcess) {
        return rep;
    }

    auto pfnQuery = NtApiLoader::get_nt_query_information_process();
    if (!pfnQuery) {
        return rep;
    }

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG ret_len = 0;
    NTSTATUS status = pfnQuery(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &ret_len
    );

    if (status != 0 || !pbi.PebBaseAddress) {
        return rep;
    }

    rep.peb_address = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);

    // Read ImageBaseAddress from PEB:
    // Offset 0x10 for 64-bit, 0x08 for 32-bit
    const size_t image_base_offset = is_64bit ? 0x10 : 0x08;
    uint64_t image_base = 0;
    SIZE_T bytes_read = 0;

    if (is_64bit) {
        if (!ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(rep.peb_address + image_base_offset),
            &image_base,
            sizeof(uint64_t),
            &bytes_read
        ) || bytes_read != sizeof(uint64_t)) {
            return rep;
        }
    } else {
        uint32_t image_base32 = 0;
        if (!ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(rep.peb_address + image_base_offset),
            &image_base32,
            sizeof(uint32_t),
            &bytes_read
        ) || bytes_read != sizeof(uint32_t)) {
            return rep;
        }
        image_base = image_base32;
    }

    rep.in_memory_image_base = image_base;
    if (image_base == 0) {
        return rep;
    }

    // Check virtual memory allocation type at image_base
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(image_base), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.Type == MEM_PRIVATE) {
            HollowingAnomaly an{};
            an.type = HollowingAnomalyType::UnmappedImageBase;
            an.description = L"Process ImageBase is allocated as MEM_PRIVATE instead of MEM_IMAGE (Unmapped PE / Process Hollowed)";
            an.is_critical = true;
            rep.anomalies.push_back(std::move(an));
            rep.is_hollowed = true;
        }
    }

    // Read in-memory DOS Header
    IMAGE_DOS_HEADER in_mem_dos{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(image_base), &in_mem_dos, sizeof(in_mem_dos), &bytes_read) ||
        in_mem_dos.e_magic != IMAGE_DOS_SIGNATURE) {
        HollowingAnomaly an{};
        an.type = HollowingAnomalyType::HeadersCorrupted;
        an.description = L"In-memory PE DOS signature (MZ) missing or zeroed (Header Stomping)";
        an.is_critical = true;
        rep.anomalies.push_back(std::move(an));
        return rep;
    }

    uint32_t in_mem_ep_rva = 0;
    uint32_t in_mem_size_of_image = 0;

    if (is_64bit) {
        IMAGE_NT_HEADERS64 in_mem_nth{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(image_base + in_mem_dos.e_lfanew), &in_mem_nth, sizeof(in_mem_nth), &bytes_read) ||
            in_mem_nth.Signature != IMAGE_NT_SIGNATURE) {
            HollowingAnomaly an{};
            an.type = HollowingAnomalyType::HeadersCorrupted;
            an.description = L"In-memory PE NT signature (PE\\0\\0) corrupted or unreadable";
            an.is_critical = true;
            rep.anomalies.push_back(std::move(an));
            return rep;
        }
        in_mem_ep_rva = in_mem_nth.OptionalHeader.AddressOfEntryPoint;
        in_mem_size_of_image = in_mem_nth.OptionalHeader.SizeOfImage;
    } else {
        IMAGE_NT_HEADERS32 in_mem_nth32{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(image_base + in_mem_dos.e_lfanew), &in_mem_nth32, sizeof(in_mem_nth32), &bytes_read) ||
            in_mem_nth32.Signature != IMAGE_NT_SIGNATURE) {
            HollowingAnomaly an{};
            an.type = HollowingAnomalyType::HeadersCorrupted;
            an.description = L"In-memory PE NT signature (PE\\0\\0) corrupted or unreadable";
            an.is_critical = true;
            rep.anomalies.push_back(std::move(an));
            return rep;
        }
        in_mem_ep_rva = in_mem_nth32.OptionalHeader.AddressOfEntryPoint;
        in_mem_size_of_image = in_mem_nth32.OptionalHeader.SizeOfImage;
    }

    rep.in_memory_entry_point = image_base + in_mem_ep_rva;

    // Check entry point instructions in memory
    uint8_t ep_bytes[16]{0};
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(rep.in_memory_entry_point), ep_bytes, sizeof(ep_bytes), &bytes_read) && bytes_read >= 4) {
        // Check for JMP rel32 (0xE9), JMP indirect (0xFF 0x25), RET (0xC3), INT 3 (0xCC)
        if (ep_bytes[0] == 0xE9 || (ep_bytes[0] == 0xFF && ep_bytes[1] == 0x25) || ep_bytes[0] == 0xC3 || ep_bytes[0] == 0xCC) {
            HollowingAnomaly an{};
            an.type = HollowingAnomalyType::EntryPointHooked;
            an.description = L"Entry point begins with redirection instruction (JMP, RET, or INT 3)";
            an.actual_value = rep.in_memory_entry_point;
            an.preview_bytes.assign(ep_bytes, ep_bytes + bytes_read);
            an.is_critical = true;
            rep.anomalies.push_back(std::move(an));
        }
    }

    // Now compare against on-disk binary if file path is available
    if (!image_path.empty()) {
        HANDLE hFile = CreateFileW(
            image_path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            IMAGE_DOS_HEADER disk_dos{};
            DWORD dwRead = 0;
            if (ReadFile(hFile, &disk_dos, sizeof(disk_dos), &dwRead, nullptr) && disk_dos.e_magic == IMAGE_DOS_SIGNATURE) {
                SetFilePointer(hFile, disk_dos.e_lfanew, nullptr, FILE_BEGIN);
                if (is_64bit) {
                    IMAGE_NT_HEADERS64 disk_nth{};
                    if (ReadFile(hFile, &disk_nth, sizeof(disk_nth), &dwRead, nullptr) && disk_nth.Signature == IMAGE_NT_SIGNATURE) {
                        rep.on_disk_entry_point = disk_nth.OptionalHeader.AddressOfEntryPoint;
                        if (in_mem_ep_rva != disk_nth.OptionalHeader.AddressOfEntryPoint) {
                            HollowingAnomaly an{};
                            an.type = HollowingAnomalyType::EntryPointMismatch;
                            an.description = L"In-memory EntryPoint RVA does not match on-disk binary headers";
                            an.expected_value = disk_nth.OptionalHeader.AddressOfEntryPoint;
                            an.actual_value = in_mem_ep_rva;
                            an.is_critical = true;
                            rep.anomalies.push_back(std::move(an));
                            rep.is_hollowed = true;
                        }

                        if (in_mem_size_of_image != disk_nth.OptionalHeader.SizeOfImage) {
                            HollowingAnomaly an{};
                            an.type = HollowingAnomalyType::ImageSizeMismatch;
                            an.description = L"In-memory SizeOfImage does not match on-disk binary headers";
                            an.expected_value = disk_nth.OptionalHeader.SizeOfImage;
                            an.actual_value = in_mem_size_of_image;
                            an.is_critical = false;
                            rep.anomalies.push_back(std::move(an));
                        }
                    }
                } else {
                    IMAGE_NT_HEADERS32 disk_nth32{};
                    if (ReadFile(hFile, &disk_nth32, sizeof(disk_nth32), &dwRead, nullptr) && disk_nth32.Signature == IMAGE_NT_SIGNATURE) {
                        rep.on_disk_entry_point = disk_nth32.OptionalHeader.AddressOfEntryPoint;
                        if (in_mem_ep_rva != disk_nth32.OptionalHeader.AddressOfEntryPoint) {
                            HollowingAnomaly an{};
                            an.type = HollowingAnomalyType::EntryPointMismatch;
                            an.description = L"In-memory EntryPoint RVA does not match on-disk binary headers";
                            an.expected_value = disk_nth32.OptionalHeader.AddressOfEntryPoint;
                            an.actual_value = in_mem_ep_rva;
                            an.is_critical = true;
                            rep.anomalies.push_back(std::move(an));
                            rep.is_hollowed = true;
                        }
                    }
                }
            }
            CloseHandle(hFile);
        }
    }

    return rep;
}

} // namespace vmemscan
