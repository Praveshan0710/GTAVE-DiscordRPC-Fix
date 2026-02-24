#include "nt.h"

NtApi g_Nt{};

bool InitNtApi()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;

#define RESOLVE(x) \
    g_Nt.x = (x##_t)GetProcAddress(ntdll, #x); \
    if (!g_Nt.x) { \
        return false; \
    }

    RESOLVE(NtQuerySystemInformation);
    RESOLVE(NtDuplicateObject);
    RESOLVE(NtQueryObject);
    RESOLVE(NtQueryInformationProcess);
    RESOLVE(RtlGetNtVersionNumbers);

#undef RESOLVE

    return true;
}