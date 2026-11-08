#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>

#include <cstdint>

namespace vmemscan {

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress static_cast<THREADINFOCLASS>(9)
#endif

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

class NtApiLoader {
public:
    static pfnNtQueryInformationProcess get_nt_query_information_process() {
        static pfnNtQueryInformationProcess fn = reinterpret_cast<pfnNtQueryInformationProcess>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess")
        );
        return fn;
    }

    static pfnNtQueryInformationThread get_nt_query_information_thread() {
        static pfnNtQueryInformationThread fn = reinterpret_cast<pfnNtQueryInformationThread>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread")
        );
        return fn;
    }
};

} // namespace vmemscan
