#include "vmemscan/section_auditor.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace vmemscan {

std::wstring SectionAuditor::anomaly_type_to_string(SectionAnomalyType type) {
    switch (type) {
    case SectionAnomalyType::None:                       return L"None";
    case SectionAnomalyType::AnonymousExecutableSection: return L"Anonymous Executable Section (MEM_MAPPED Shellcode)";
    case SectionAnomalyType::DataFileExecutableSection:  return L"Executable Section Backed by Data File";
    case SectionAnomalyType::RwxSection:                return L"RWX Mapped Section (W^X Breach)";
    case SectionAnomalyType::SectionProtectionPromotion: return L"Section Protection Elevation (Non-Exec to Executable)";
    default:                                             return L"Unknown";
    }
}

static std::wstring prot_to_string(uint32_t p) {
    switch (p & 0xFF) {
    case PAGE_NOACCESS:          return L"PAGE_NOACCESS";
    case PAGE_READONLY:          return L"PAGE_READONLY";
    case PAGE_READWRITE:         return L"PAGE_READWRITE";
    case PAGE_WRITECOPY:         return L"PAGE_WRITECOPY";
    case PAGE_EXECUTE:           return L"PAGE_EXECUTE";
    case PAGE_EXECUTE_READ:      return L"PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return L"PAGE_EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return L"PAGE_EXECUTE_WRITECOPY";
    default:                     return L"PAGE_UNKNOWN";
    }
}

static bool is_data_file_extension(const std::wstring& path) {
    if (path.empty()) return false;
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    return (ext == L".dat" || ext == L".tmp" || ext == L".txt" ||
            ext == L".bin" || ext == L".png" || ext == L".jpg" ||
            ext == L".log" || ext == L".cfg" || ext == L".ini");
}

std::vector<SectionAnomaly> SectionAuditor::evaluate_sections(
    const std::vector<MemoryRegion>& regions
) {
    std::vector<SectionAnomaly> anomalies;

    for (const auto& reg : regions) {
        if (reg.type != MEM_MAPPED || reg.state != MEM_COMMIT) {
            continue;
        }

        bool is_exec = reg.is_executable || ((reg.protect & 0xF0) != 0);
        bool alloc_non_exec = ((reg.alloc_protect & 0xF0) == 0) && (reg.alloc_protect != 0);

        // 1. Anonymous Executable Section (No disk backing file)
        if (is_exec && reg.mapped_file.empty()) {
            SectionAnomaly a{};
            a.base_address = reg.base_address;
            a.region_size = reg.region_size;
            a.memory_protection = reg.protect;
            a.protection_string = prot_to_string(reg.protect);
            a.mapped_file = L"<anonymous_section>";
            a.type = SectionAnomalyType::AnonymousExecutableSection;
            a.is_critical = true;

            std::wostringstream oss;
            oss << L"Committed MEM_MAPPED region at 0x" << std::hex << reg.base_address
                << L" has executable rights (" << a.protection_string
                << L") without a disk backing file (section view shellcode injection)";
            a.details = oss.str();
            anomalies.push_back(a);
            continue;
        }

        // 2. Executable Section Backed by Data File
        if (is_exec && is_data_file_extension(reg.mapped_file)) {
            SectionAnomaly a{};
            a.base_address = reg.base_address;
            a.region_size = reg.region_size;
            a.memory_protection = reg.protect;
            a.protection_string = prot_to_string(reg.protect);
            a.mapped_file = reg.mapped_file;
            a.type = SectionAnomalyType::DataFileExecutableSection;
            a.is_critical = true;

            std::wostringstream oss;
            oss << L"Committed MEM_MAPPED region at 0x" << std::hex << reg.base_address
                << L" is mapped from non-executable data file (" << reg.mapped_file
                << L") with executable permissions (" << a.protection_string << L")";
            a.details = oss.str();
            anomalies.push_back(a);
            continue;
        }

        // 3. RWX Section
        if (reg.is_rwx) {
            SectionAnomaly a{};
            a.base_address = reg.base_address;
            a.region_size = reg.region_size;
            a.memory_protection = reg.protect;
            a.protection_string = prot_to_string(reg.protect);
            a.mapped_file = reg.mapped_file.empty() ? L"<anonymous_section>" : reg.mapped_file;
            a.type = SectionAnomalyType::RwxSection;
            a.is_critical = true;

            std::wostringstream oss;
            oss << L"Mapped section view at 0x" << std::hex << reg.base_address
                << L" has PAGE_EXECUTE_READWRITE permissions (W^X mitigation breach)";
            a.details = oss.str();
            anomalies.push_back(a);
            continue;
        }

        // 4. Section Protection Promotion (Allocated non-exec, elevated to executable at runtime)
        if (alloc_non_exec && is_exec) {
            SectionAnomaly a{};
            a.base_address = reg.base_address;
            a.region_size = reg.region_size;
            a.memory_protection = reg.protect;
            a.protection_string = prot_to_string(reg.protect);
            a.mapped_file = reg.mapped_file.empty() ? L"<anonymous_section>" : reg.mapped_file;
            a.type = SectionAnomalyType::SectionProtectionPromotion;
            a.is_critical = false;

            std::wostringstream oss;
            oss << L"Mapped section view at 0x" << std::hex << reg.base_address
                << L" was allocated as non-executable (" << prot_to_string(reg.alloc_protect)
                << L") but elevated to executable (" << a.protection_string << L")";
            a.details = oss.str();
            anomalies.push_back(a);
        }
    }

    return anomalies;
}

SectionAuditReport SectionAuditor::audit_process_sections(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::vector<MemoryRegion>& regions
) {
    (void)hProcess;
    SectionAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    for (const auto& r : regions) {
        if (r.type == MEM_MAPPED && r.state == MEM_COMMIT) {
            ++rep.mapped_regions_count;
            if (r.is_executable || ((r.protect & 0xF0) != 0)) {
                ++rep.executable_sections_count;
            }
        }
    }

    rep.anomalies = evaluate_sections(regions);
    rep.anomalous_sections_count = rep.anomalies.size();

    return rep;
}

} // namespace vmemscan
