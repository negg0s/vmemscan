#include "vmemscan/module_stomping_detector.hpp"

#include <algorithm>
#include <tlhelp32.h>

namespace vmemscan {

bool ModuleStompingDetector::compare_section_prologue(
    const uint8_t* disk_bytes,
    const uint8_t* mem_bytes,
    size_t size,
    size_t& divergence_count
) {
    divergence_count = 0;
    if (!disk_bytes || !mem_bytes || size < 16) {
        return false;
    }

    for (size_t i = 0; i < size; ++i) {
        if (disk_bytes[i] != mem_bytes[i]) {
            ++divergence_count;
        }
    }

    // Check if memory has been modified with shellcode or JMP trampoline
    // First 4 bytes replaced with JMP/CALL or classic shellcode
    bool has_trampoline_overwrite = (mem_bytes[0] == 0xE9 || mem_bytes[0] == 0xE8 || mem_bytes[0] == 0xCC ||
                                    (mem_bytes[0] == 0xFF && mem_bytes[1] == 0x25)) &&
                                    (disk_bytes[0] != mem_bytes[0]);

    // If more than 16 bytes differ out of 256 or trampoline placed at entry
    return (divergence_count >= 16 || has_trampoline_overwrite);
}

ModuleStompingReport ModuleStompingDetector::audit_process_module_stomping(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    bool is_64bit
) {
    (void)is_64bit;
    ModuleStompingReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || pid == 0) {
        return rep;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return rep;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    auto is_skip_module = [](const std::wstring& mod_name) -> bool {
        std::wstring s = mod_name;
        for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
        return (s == L"ntdll.dll" || s == L"win32u.dll");
    };

    if (Module32FirstW(hSnap, &me)) {
        do {
            if (is_skip_module(me.szModule)) {
                continue;
            }

            ++rep.modules_evaluated;

            HANDLE hFile = CreateFileW(
                me.szExePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                continue;
            }

            IMAGE_DOS_HEADER dos{};
            DWORD read = 0;
            if (!ReadFile(hFile, &dos, sizeof(dos), &read, nullptr) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
                CloseHandle(hFile);
                continue;
            }

            SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN);
            IMAGE_NT_HEADERS64 nth{};
            if (!ReadFile(hFile, &nth, sizeof(nth), &read, nullptr) || nth.Signature != IMAGE_NT_SIGNATURE) {
                CloseHandle(hFile);
                continue;
            }

            const size_t num_sec = nth.FileHeader.NumberOfSections;
            std::vector<IMAGE_SECTION_HEADER> sections(num_sec);
            if (!ReadFile(hFile, sections.data(), static_cast<DWORD>(num_sec * sizeof(IMAGE_SECTION_HEADER)), &read, nullptr)) {
                CloseHandle(hFile);
                continue;
            }

            for (const auto& sec : sections) {
                char sname[9]{0};
                memcpy(sname, sec.Name, 8);
                std::string sec_str = sname;

                // Target code sections (.text or code flag)
                if (sec_str == ".text" || (sec.Characteristics & IMAGE_SCN_CNT_CODE)) {
                    if (sec.SizeOfRawData < 64 || sec.VirtualAddress == 0) {
                        continue;
                    }

                    const size_t sample_size = (std::min)(static_cast<size_t>(256), static_cast<size_t>(sec.SizeOfRawData));
                    std::vector<uint8_t> disk_buf(sample_size);
                    std::vector<uint8_t> mem_buf(sample_size);

                    SetFilePointer(hFile, sec.PointerToRawData, nullptr, FILE_BEGIN);
                    if (!ReadFile(hFile, disk_buf.data(), static_cast<DWORD>(sample_size), &read, nullptr) || read != sample_size) {
                        continue;
                    }

                    uint64_t mem_sec_addr = reinterpret_cast<uint64_t>(me.modBaseAddr) + sec.VirtualAddress;
                    SIZE_T mem_read = 0;
                    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(mem_sec_addr), mem_buf.data(), sample_size, &mem_read) || mem_read != sample_size) {
                        continue;
                    }

                    size_t divergence = 0;
                    if (compare_section_prologue(disk_buf.data(), mem_buf.data(), sample_size, divergence)) {
                        StompedModuleFinding f{};
                        f.module_name = me.szModule;
                        f.module_path = me.szExePath;
                        f.module_base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                        f.section_name = sec_str;
                        f.section_address = mem_sec_addr;
                        f.bytes_divergent = divergence;
                        f.stomping_type = L"Code Section Tampering / Module Stomping";

                        size_t preview_len = (std::min)(static_cast<size_t>(16), sample_size);
                        f.in_memory_bytes.assign(mem_buf.begin(), mem_buf.begin() + preview_len);
                        f.on_disk_bytes.assign(disk_buf.begin(), disk_buf.begin() + preview_len);

                        rep.findings.push_back(std::move(f));
                    }
                    break;
                }
            }

            CloseHandle(hFile);

        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    rep.stomped_modules_count = rep.findings.size();
    return rep;
}

} // namespace vmemscan
