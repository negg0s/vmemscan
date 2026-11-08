#include "vmemscan/privileges.hpp"

namespace vmemscan {

bool PrivilegeManager::is_elevated_admin() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_ELEVATION elevation{};
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    bool elevated = false;

    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
        elevated = (elevation.TokenIsElevated != 0);
    }

    CloseHandle(hToken);
    return elevated;
}

bool PrivilegeManager::enable_privilege(const wchar_t* privilege_name) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privilege_name, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(hToken);

    return (ok && err == ERROR_SUCCESS);
}

bool PrivilegeManager::enable_debug_privilege() {
    return enable_privilege(SE_DEBUG_NAME);
}

} // namespace vmemscan
