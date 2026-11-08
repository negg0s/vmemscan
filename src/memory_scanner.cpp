#include "vmemscan/memory_scanner.hpp"

#include <psapi.h>

namespace vmemscan {

std::wstring MemoryScanner::protect_to_string(uint32_t protect) {
    const uint32_t base = protect & 0xFF;
    std::wstring s;

    switch (base) {
    case PAGE_NOACCESS:          s = L"---"; break;
    case PAGE_READONLY:          s = L"R--"; break;
    case PAGE_READWRITE:         s = L"RW-"; break;
    case PAGE_WRITECOPY:         s = L"RC-"; break;
    case PAGE_EXECUTE:           s = L"--X"; break;
    case PAGE_EXECUTE_READ:      s = L"R-X"; break;
    case PAGE_EXECUTE_READWRITE: s = L"RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: s = L"RCX"; break;
    default:                     s = L"???"; break;
    }

    if (protect & PAGE_GUARD) s += L"+G";
    if (protect & PAGE_NOCACHE) s += L"+NC";
    if (protect & PAGE_WRITECOMBINE) s += L"+WC";
    return s;
}

std::wstring MemoryScanner::state_to_string(uint32_t state) {
    switch (state) {
    case MEM_COMMIT:  return L"COMMIT";
    case MEM_RESERVE: return L"RESERVE";
    case MEM_FREE:    return L"FREE";
    default:          return L"UNKNOWN";
    }
}

std::wstring MemoryScanner::type_to_string(uint32_t type) {
    switch (type) {
    case MEM_IMAGE:   return L"IMAGE";
    case MEM_MAPPED:  return L"MAPPED";
    case MEM_PRIVATE: return L"PRIVATE";
    default:          return L"NONE";
    }
}

Result<std::vector<MemoryRegion>> MemoryScanner::scan_process_memory(
    HANDLE hProcess,
    const MemoryFilter& filter
) {
    if (!hProcess) {
        return Error(ERROR_INVALID_HANDLE, L"Invalid process handle");
    }

    std::vector<MemoryRegion> regions;
    uint8_t* current_addr = nullptr;

    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQueryEx(hProcess, current_addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            const bool is_exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            const bool is_write = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            const bool is_rwx = (mbi.Protect == PAGE_EXECUTE_READWRITE);

            std::wstring mapped_file;
            if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                wchar_t mapped_path[MAX_PATH * 2]{0};
                if (GetMappedFileNameW(hProcess, mbi.BaseAddress, mapped_path, static_cast<DWORD>(sizeof(mapped_path) / sizeof(wchar_t)))) {
                    mapped_file = mapped_path;
                }
            }

            const bool is_unbacked = is_exec && (mbi.Type == MEM_PRIVATE || (mbi.Type == MEM_MAPPED && mapped_file.empty()));

            bool keep = true;
            if (filter.only_executable && !is_exec) keep = false;
            if (filter.only_unbacked && !is_unbacked) keep = false;
            if (filter.only_rwx && !is_rwx) keep = false;
            if (filter.only_private && mbi.Type != MEM_PRIVATE) keep = false;
            if (filter.min_size != 0 && mbi.RegionSize < filter.min_size) keep = false;

            if (keep) {
                MemoryRegion r{};
                r.base_address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                r.allocation_base = reinterpret_cast<uint64_t>(mbi.AllocationBase);
                r.region_size = mbi.RegionSize;
                r.state = mbi.State;
                r.protect = mbi.Protect;
                r.alloc_protect = mbi.AllocationProtect;
                r.type = mbi.Type;
                r.mapped_file = mapped_file;
                r.is_executable = is_exec;
                r.is_writable = is_write;
                r.is_unbacked_executable = is_unbacked;
                r.is_rwx = is_rwx;
                regions.push_back(std::move(r));
            }
        }

        uint8_t* next_addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next_addr <= current_addr) {
            break; // Overflow prevention / end of address space
        }
        current_addr = next_addr;
    }

    return regions;
}

ProcessMemorySummary MemoryScanner::compute_summary(
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    ProcessMemorySummary s{};
    s.pid = pid;
    s.process_name = process_name;
    s.total_regions = regions.size();

    for (const auto& r : regions) {
        if (r.state == MEM_COMMIT) {
            ++s.committed_regions;
            s.total_committed_bytes += r.region_size;

            if (r.type == MEM_PRIVATE) s.total_private_bytes += r.region_size;
            else if (r.type == MEM_MAPPED) s.total_mapped_bytes += r.region_size;
            else if (r.type == MEM_IMAGE) s.total_image_bytes += r.region_size;

            if (r.is_executable) {
                s.executable_bytes += r.region_size;
            }
            if (r.is_unbacked_executable) {
                s.unbacked_executable_bytes += r.region_size;
                ++s.unbacked_executable_regions_count;
            }
            if (r.is_rwx) {
                s.rwx_bytes += r.region_size;
                ++s.rwx_regions_count;
            }
        }
    }

    return s;
}

} // namespace vmemscan
