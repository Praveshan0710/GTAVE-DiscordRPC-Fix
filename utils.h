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

namespace GTA
{
    inline constexpr wchar_t ProcessName[] = L"gta5_enhanced.exe";
    inline constexpr wchar_t FileName[] = L"title.rgl";
    inline constexpr wchar_t UpdateDirName[] = L"\\update\\x64";
    inline constexpr const wchar_t* FlagFiles[] = {
        L"args.txt",
        L"commandline.txt"
    };
}

//namespace GTA
//{
//    const std::wstring ProcessName = L"gta5_enhanced.exe";
//    const std::wstring FileName = L"title.rgl";
//    const std::wstring UpdateDirName = L"\\update\\x64";
//}

std::pair<DWORD, std::wstring> FindProcessAndPath(const std::wstring& processName);
std::wstring GetDirectoryFromPath(const std::wstring& fullPath);
std::wstring NormalizePathForComparison(std::wstring path);
std::set<ULONG_PTR> GetProcessHandles(DWORD pid);
bool CheckHandlesForFile(DWORD pid, const std::set<ULONG_PTR>& newHandles, const std::wstring& targetFile);
std::wstring GetProcessCommandLine(DWORD pid);
bool HasForceWin32InFile(const std::wstring& dir, const std::wstring& filename);
bool IsWindows11();
bool IsGameDriveNvme(const std::wstring& exePath);
bool IsUsingDirectStorage(DWORD pid, const std::wstring& exePath, const std::wstring& dir);
std::vector<std::wstring> GetGTAInstallPaths();
void RemoveTitleRgl(const std::wstring& installPath);
void PauseExit();