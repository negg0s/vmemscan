#include "vmemscan/memory_dumper.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace vmemscan {

uint64_t MemoryDumper::compute_fnv1a(const uint8_t* data, size_t size) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= 1099511628211ULL;
    }
    return hash;
}

Result<DumpResult> MemoryDumper::dump_region(
    HANDLE hProcess,
    uint32_t pid,
    uint64_t address,
    uint64_t size,
    const std::wstring& out_path,
    bool fixup_pe
) {
    if (!hProcess) {
        return Error(ERROR_INVALID_HANDLE, L"Invalid process handle");
    }

    if (size == 0) {
        return Error(ERROR_INVALID_PARAMETER, L"Region size is zero");
    }

    constexpr uint64_t MAX_DUMP_SIZE = 512ULL * 1024ULL * 1024ULL; // 512 MB safety ceiling
    if (size > MAX_DUMP_SIZE) {
        return Error(ERROR_NOT_ENOUGH_MEMORY, L"Requested dump size exceeds maximum allowed limit (512 MB)");
    }

    std::wstring final_path = out_path;
    if (final_path.empty()) {
        std::wostringstream oss;
        oss << L"dump_pid" << pid << L"_addr0x" << std::hex << std::uppercase << address << L".bin";
        final_path = oss.str();
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    SIZE_T bytes_read = 0;

    const BOOL ok = ReadProcessMemory(
        hProcess,
        reinterpret_cast<LPCVOID>(address),
        buffer.data(),
        buffer.size(),
        &bytes_read
    );

    if (!ok && bytes_read == 0) {
        return Error(GetLastError(), L"ReadProcessMemory failed for address 0x" + std::to_wstring(address));
    }

    buffer.resize(bytes_read);

    DumpResult res{};
    res.pid = pid;
    res.base_address = address;
    res.bytes_requested = size;
    res.bytes_dumped = bytes_read;
    res.output_path = final_path;
    res.fnv1a_hash = compute_fnv1a(buffer.data(), buffer.size());

    // Check if starts with MZ header
    if (buffer.size() >= sizeof(IMAGE_DOS_HEADER)) {
        const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dos_hdr->e_magic == IMAGE_DOS_SIGNATURE && dos_hdr->e_lfanew > 0 &&
            static_cast<size_t>(dos_hdr->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= buffer.size()) {
            res.is_pe_image = true;

            if (fixup_pe) {
                // Adjust section alignment and raw pointers so PE analyzers can read section data
                auto* nt_hdr = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dos_hdr->e_lfanew);
                if (nt_hdr->Signature == IMAGE_NT_SIGNATURE) {
                    const WORD num_sections = (std::min)(nt_hdr->FileHeader.NumberOfSections, static_cast<WORD>(96));
                    const size_t opt_hdr_size = nt_hdr->FileHeader.SizeOfOptionalHeader;
                    const size_t sec_table_offset = static_cast<size_t>(dos_hdr->e_lfanew) +
                                                    sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + opt_hdr_size;

                    if (sec_table_offset + (num_sections * sizeof(IMAGE_SECTION_HEADER)) <= buffer.size()) {
                        auto* sec_hdr = reinterpret_cast<IMAGE_SECTION_HEADER*>(buffer.data() + sec_table_offset);
                        for (WORD i = 0; i < num_sections; ++i) {
                            sec_hdr[i].PointerToRawData = sec_hdr[i].VirtualAddress;
                            sec_hdr[i].SizeOfRawData = sec_hdr[i].Misc.VirtualSize;
                        }
                        res.pe_reconstructed = true;
                    }
                }
            }
        }
    }

    std::filesystem::path fp(final_path);
    if (fp.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(fp.parent_path(), ec);
    }

    std::ofstream out(final_path, std::ios::binary);
    if (!out.is_open()) {
        return Error(ERROR_CANNOT_MAKE, L"Failed to create output file: " + final_path);
    }

    out.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    out.close();

    return res;
}

} // namespace vmemscan
