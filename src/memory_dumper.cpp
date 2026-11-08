#include "vmemscan/memory_dumper.hpp"

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
            static_cast<size_t>(dos_hdr->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) <= buffer.size()) {
            res.is_pe_image = true;

            if (fixup_pe) {
                // Adjust section alignment and raw pointers so PE analyzers can read section data
                auto* nt_hdr = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dos_hdr->e_lfanew);
                if (nt_hdr->Signature == IMAGE_NT_SIGNATURE) {
                    const WORD num_sections = nt_hdr->FileHeader.NumberOfSections;
                    auto* sec_hdr = IMAGE_FIRST_SECTION(nt_hdr);

                    for (WORD i = 0; i < num_sections; ++i) {
                        if (reinterpret_cast<const uint8_t*>(sec_hdr + 1) > buffer.data() + buffer.size()) {
                            break;
                        }
                        sec_hdr->PointerToRawData = sec_hdr->VirtualAddress;
                        sec_hdr->SizeOfRawData = sec_hdr->Misc.VirtualSize;
                        ++sec_hdr;
                    }
                    res.pe_reconstructed = true;
                }
            }
        }
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
