#include "vmemscan/iat_hook_detector.hpp"
#include "vmemscan/nt_defs.hpp"

#include <vector>

namespace vmemscan {

IatHookReport IatHookDetector::audit_process_iat(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    bool is_64bit,
    const std::vector<MemoryRegion>& regions,
    uint64_t image_base
) {
    IatHookReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || !is_64bit) {
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

    if (image_base == 0) {
        return rep;
    }

    auto find_region = [&](uint64_t addr) -> const MemoryRegion* {
        if (addr == 0) return nullptr;
        for (const auto& r : regions) {
            if (addr >= r.base_address && addr < r.base_address + r.region_size) {
                return &r;
            }
        }
        return nullptr;
    };

    IMAGE_DOS_HEADER dos{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(image_base), &dos, sizeof(dos), &read) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return rep;
    }

    IMAGE_NT_HEADERS64 nth{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(image_base + dos.e_lfanew), &nth, sizeof(nth), &read) || nth.Signature != IMAGE_NT_SIGNATURE) {
        return rep;
    }

    const auto& imp_dir = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) {
        return rep;
    }

    uint64_t desc_addr = image_base + imp_dir.VirtualAddress;

    for (size_t d_idx = 0; d_idx < 100; ++d_idx) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(desc_addr + (d_idx * sizeof(desc))), &desc, sizeof(desc), &read) ||
            (desc.Name == 0 && desc.FirstThunk == 0)) {
            break;
        }

        char mod_name_buf[128]{0};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(image_base + desc.Name), mod_name_buf, sizeof(mod_name_buf) - 1, &read)) {
            continue;
        }

        std::string mod_name_str = mod_name_buf;
        std::wstring imported_mod(mod_name_str.begin(), mod_name_str.end());

        uint64_t thunk_addr = image_base + (desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk);
        uint64_t iat_addr = image_base + desc.FirstThunk;

        for (size_t t_idx = 0; t_idx < 500; ++t_idx) {
            uint64_t thunk_data = 0;
            uint64_t func_ptr = 0;

            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(thunk_addr + (t_idx * sizeof(uint64_t))), &thunk_data, sizeof(thunk_data), &read) || thunk_data == 0) {
                break;
            }

            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(iat_addr + (t_idx * sizeof(uint64_t))), &func_ptr, sizeof(func_ptr), &read) || func_ptr == 0) {
                break;
            }

            ++rep.total_imports_checked;

            std::string func_name;
            if (IMAGE_SNAP_BY_ORDINAL64(thunk_data)) {
                func_name = "Ordinal#" + std::to_string(IMAGE_ORDINAL64(thunk_data));
            } else {
                uint64_t ibn_addr = image_base + (thunk_data & 0x7FFFFFFF);
                WORD hint = 0;
                char fname_buf[128]{0};
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(ibn_addr + sizeof(hint)), fname_buf, sizeof(fname_buf) - 1, &read)) {
                    func_name = fname_buf;
                }
            }

            const auto* reg = find_region(func_ptr);
            if (reg) {
                bool suspicious = false;
                std::wstring desc_text;

                if (reg->is_unbacked_executable) {
                    suspicious = true;
                    desc_text = L"IAT entry points to unbacked private memory (Inline redirection / Hook)";
                } else if (reg->is_rwx) {
                    suspicious = true;
                    desc_text = L"IAT entry points to writable and executable page (W^X breach)";
                }

                if (suspicious) {
                    IatHookFinding finding{};
                    finding.imported_module = imported_mod;
                    finding.function_name = func_name;
                    finding.iat_entry_address = iat_addr + (t_idx * sizeof(uint64_t));
                    finding.actual_function_pointer = func_ptr;
                    finding.points_to_unbacked = reg->is_unbacked_executable;
                    finding.points_to_rwx = reg->is_rwx;
                    finding.actual_mapped_module = reg->mapped_file;
                    finding.hook_description = desc_text;

                    rep.findings.push_back(std::move(finding));
                }
            }
        }
    }

    rep.hooked_imports_count = rep.findings.size();
    return rep;
}

} // namespace vmemscan
