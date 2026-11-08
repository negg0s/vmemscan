#include "vmemscan/peb_auditor.hpp"
#include "vmemscan/nt_defs.hpp"

#include <algorithm>

namespace vmemscan {

std::wstring PebAuditor::anomaly_to_string(PebAnomalyType type) {
    switch (type) {
    case PebAnomalyType::None:                  return L"None";
    case PebAnomalyType::ImagePathSpoofing:     return L"Image Path / Command-Line Spoofing (PEB mismatch)";
    case PebAnomalyType::EmptyCommandLine:      return L"Empty or Stripped Command Line";
    case PebAnomalyType::DotNetProfilingHijack: return L".NET CLR Profiling DLL Hijacking Flag (COR_ENABLE_PROFILING)";
    case PebAnomalyType::SuspiciousEnvironment: return L"Suspicious Environment Variable Setting";
    default:                                    return L"Unknown";
    }
}

static std::wstring read_remote_unicode_string(HANDLE hProcess, uint64_t ustr_addr) {
    UNICODE_STRING us{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(ustr_addr), &us, sizeof(us), &read) || us.Length == 0 || !us.Buffer) {
        return {};
    }

    const size_t char_count = us.Length / sizeof(wchar_t);
    std::vector<wchar_t> buf(char_count + 1, 0);
    if (!ReadProcessMemory(hProcess, us.Buffer, buf.data(), us.Length, &read) || read == 0) {
        return {};
    }

    return std::wstring(buf.data(), read / sizeof(wchar_t));
}

PebAuditReport PebAuditor::audit_process_peb(
    HANDLE hProcess,
    uint32_t pid,
    const std::wstring& process_name,
    const std::wstring& real_image_path,
    bool is_64bit
) {
    PebAuditReport rep{};
    rep.pid = pid;
    rep.process_name = process_name;

    if (!hProcess || !is_64bit) {
        return rep;
    }

    auto pfnQuery = NtApiLoader::get_nt_query_information_process();
    if (!pfnQuery) {
        return rep;
    }

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG ret_len = 0;
    if (pfnQuery(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len) != 0 || !pbi.PebBaseAddress) {
        return rep;
    }

    rep.peb_address = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);

    // Read ProcessParameters pointer at offset 0x20 of PEB
    uint64_t proc_params_ptr = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(rep.peb_address + 0x20), &proc_params_ptr, sizeof(proc_params_ptr), &read) || !proc_params_ptr) {
        return rep;
    }

    rep.process_parameters_address = proc_params_ptr;

    // Read ImagePathName at offset 0x60
    rep.image_path_name = read_remote_unicode_string(hProcess, proc_params_ptr + 0x60);

    // Read CommandLine at offset 0x70
    rep.command_line = read_remote_unicode_string(hProcess, proc_params_ptr + 0x70);

    // Read CurrentDirectory at offset 0x38
    rep.current_directory = read_remote_unicode_string(hProcess, proc_params_ptr + 0x38);

    // Compare ImagePathName against real_image_path
    if (!real_image_path.empty() && !rep.image_path_name.empty()) {
        std::wstring p1 = real_image_path;
        std::wstring p2 = rep.image_path_name;
        for (auto& c : p1) c = static_cast<wchar_t>(towlower(c));
        for (auto& c : p2) c = static_cast<wchar_t>(towlower(c));

        // Strip \??\ or \\?\ prefix
        if (p2.rfind(L"\\??\\", 0) == 0) p2 = p2.substr(4);
        if (p2.rfind(L"\\\\?\\", 0) == 0) p2 = p2.substr(4);
        if (p1.rfind(L"\\??\\", 0) == 0) p1 = p1.substr(4);
        if (p1.rfind(L"\\\\?\\", 0) == 0) p1 = p1.substr(4);

        if (p1 != p2) {
            PebAnomaly an{};
            an.type = PebAnomalyType::ImagePathSpoofing;
            an.description = L"PEB ImagePathName does not match actual disk executable path (Argument / Process Spoofing)";
            an.expected_value = real_image_path;
            an.actual_value = rep.image_path_name;
            an.is_critical = true;
            rep.anomalies.push_back(std::move(an));
        }
    }

    // Read Environment block pointer at offset 0x80
    uint64_t env_ptr = 0;
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(proc_params_ptr + 0x80), &env_ptr, sizeof(env_ptr), &read) && env_ptr) {
        // Read up to 16 KB of environment strings
        std::vector<wchar_t> env_buf(8192, 0);
        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(env_ptr), env_buf.data(), env_buf.size() * sizeof(wchar_t), &read) && read > 0) {
            const size_t total_wchars = read / sizeof(wchar_t);
            size_t idx = 0;
            while (idx < total_wchars && env_buf[idx] != L'\0') {
                std::wstring var(&env_buf[idx]);
                idx += var.size() + 1;

                std::wstring upper_var = var;
                for (auto& c : upper_var) c = static_cast<wchar_t>(towupper(c));

                if (upper_var.find(L"COR_ENABLE_PROFILING=1") != std::wstring::npos) {
                    rep.suspicious_env_vars.push_back(var);
                    PebAnomaly an{};
                    an.type = PebAnomalyType::DotNetProfilingHijack;
                    an.description = L"COR_ENABLE_PROFILING=1 detected in environment (CLR profiler DLL hijack active)";
                    an.actual_value = var;
                    an.is_critical = true;
                    rep.anomalies.push_back(std::move(an));
                } else if (upper_var.find(L"COR_PROFILER=") != std::wstring::npos) {
                    rep.suspicious_env_vars.push_back(var);
                }
            }
        }
    }

    return rep;
}

} // namespace vmemscan
