#include "vmemscan/process_snapshot.hpp"

#include <tlhelp32.h>
#include <psapi.h>
#include <cwctype>

namespace vmemscan {

bool ProcessSnapshot::match_wildcard(const std::wstring& pattern, const std::wstring& text) {
    if (pattern.empty()) return true;

    size_t p_idx = 0;
    size_t t_idx = 0;
    size_t star_p = std::wstring::npos;
    size_t star_t = std::wstring::npos;

    while (t_idx < text.size()) {
        const wchar_t p_ch = (p_idx < pattern.size()) ? static_cast<wchar_t>(towlower(pattern[p_idx])) : L'\0';
        const wchar_t t_ch = static_cast<wchar_t>(towlower(text[t_idx]));

        if (p_idx < pattern.size() && (p_ch == L'?' || p_ch == t_ch)) {
            ++p_idx;
            ++t_idx;
        } else if (p_idx < pattern.size() && p_ch == L'*') {
            star_p = p_idx++;
            star_t = t_idx;
        } else if (star_p != std::wstring::npos) {
            p_idx = star_p + 1;
            t_idx = ++star_t;
        } else {
            return false;
        }
    }

    while (p_idx < pattern.size() && pattern[p_idx] == L'*') {
        ++p_idx;
    }

    return p_idx == pattern.size();
}

HANDLE ProcessSnapshot::open_process_for_inspection(uint32_t pid) {
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (!hProcess) {
        hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid
        );
    }
    if (!hProcess) {
        hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        );
    }
    return hProcess;
}

std::vector<ProcessInfo> ProcessSnapshot::enumerate_processes(const ProcessFilter& filter) {
    std::vector<ProcessInfo> list;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return list;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == 0) continue; // Skip System Idle Process

            if (filter.pid != 0 && pe.th32ProcessID != filter.pid) {
                continue;
            }

            if (!filter.name_pattern.empty()) {
                if (!match_wildcard(filter.name_pattern, pe.szExeFile)) {
                    continue;
                }
            }

            ProcessInfo info{};
            info.pid = pe.th32ProcessID;
            info.parent_pid = pe.th32ParentProcessID;
            info.name = pe.szExeFile;
            info.thread_count = pe.cntThreads;

            HANDLE hProc = open_process_for_inspection(info.pid);
            if (hProc) {
                wchar_t path_buf[MAX_PATH * 2]{0};
                DWORD path_len = static_cast<DWORD>(sizeof(path_buf) / sizeof(wchar_t));
                if (QueryFullProcessImageNameW(hProc, 0, path_buf, &path_len)) {
                    info.path = path_buf;
                }

                USHORT process_machine = 0;
                USHORT native_machine = 0;
                if (IsWow64Process2(hProc, &process_machine, &native_machine)) {
                    info.is_64bit = (process_machine == IMAGE_FILE_MACHINE_UNKNOWN);
                } else {
                    BOOL is_wow64 = FALSE;
                    if (IsWow64Process(hProc, &is_wow64)) {
                        info.is_64bit = !is_wow64;
                    }
                }

                HANDLE hToken = nullptr;
                if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                    TOKEN_ELEVATION elev{};
                    DWORD ret_len = 0;
                    if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &ret_len)) {
                        info.is_elevated = (elev.TokenIsElevated != 0);
                    }
                    CloseHandle(hToken);
                }

                PROCESS_MEMORY_COUNTERS_EX pmc{};
                if (GetProcessMemoryInfo(hProc, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
                    info.working_set_bytes = pmc.WorkingSetSize;
                    info.commit_bytes = pmc.PrivateUsage;
                }

                CloseHandle(hProc);
            }

            if (filter.only_64bit && !info.is_64bit) continue;
            if (filter.only_elevated && !info.is_elevated) continue;

            list.push_back(std::move(info));
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return list;
}

Result<ProcessInfo> ProcessSnapshot::get_process_by_pid(uint32_t pid) {
    ProcessFilter filter{};
    filter.pid = pid;
    auto list = enumerate_processes(filter);
    if (list.empty()) {
        return Error(ERROR_NOT_FOUND, L"Process with PID " + std::to_wstring(pid) + L" not found");
    }
    return list.front();
}

} // namespace vmemscan
