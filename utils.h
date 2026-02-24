#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <set>
#include <vector>
#include <fstream>
#include <algorithm>
#include <nvme.h>
#include <string>
#include <Aclapi.h>
#pragma comment(lib, "Advapi32.lib")

namespace GTA
{
    inline constexpr wchar_t ProcessName[] = L"GTA5_enhanced.exe";
    inline constexpr wchar_t FileName[] = L"title.rgl";
    inline constexpr wchar_t UpdateDirName[] = L"\\update\\x64";
    inline constexpr const wchar_t* FlagFiles[] = {
        L"args.txt",
        L"commandline.txt"
    };
    inline constexpr const wchar_t* InstallRegistryKeys[] =
    {
        L"SOFTWARE\\WOW6432Node\\Rockstar Games\\GTA V Enhanced", // steam
        L"SOFTWARE\\WOW6432Node\\Rockstar Games\\GTAV Enhanced" // rgl
    };
}

std::pair<DWORD, std::wstring> FindProcessAndPath(const std::wstring_view processName);
std::wstring GetDirectoryFromPath(const std::wstring& fullPath);
std::wstring NormalizePathForComparison(std::wstring path);
std::set<ULONG_PTR> GetProcessHandles(DWORD pid);
bool CheckHandlesForFile(DWORD pid, const std::set<ULONG_PTR>& newHandles, const std::wstring_view targetFile);
std::wstring GetProcessCommandLine(DWORD pid);
bool HasForceWin32InFile(const std::wstring& dir, const std::wstring_view filename);
bool IsWindows11();
bool IsGameDriveNvme(const std::wstring& exePath);
bool IsUsingDirectStorage(DWORD pid, const std::wstring& exePath, const std::wstring& dir);
std::vector<std::wstring> GetGTAInstallPaths();
bool RemoveTitleRgl(const std::wstring& installPath);
void PauseExit();
bool IsRunningAsAdmin();
bool GrantFullControlToUsers(const std::wstring& folderPath);