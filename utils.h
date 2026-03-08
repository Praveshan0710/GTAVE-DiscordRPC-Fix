#pragma once
#include <Windows.h>
#include <unordered_set>
#include <vector>
#include <string>
#include <filesystem>
#include <optional>

namespace GTA
{
    inline constexpr wchar_t ProcessName[] = L"GTA5_enhanced.exe";
    inline constexpr wchar_t TitleRgl[] = L"title.rgl";
    inline constexpr wchar_t UpdateDirName[] = L"update\\x64";
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

struct ProcessInfo
{
    DWORD pid;
    std::filesystem::path directory;
};

std::optional<ProcessInfo> FindProcessIdAndDirectory(const wchar_t* processName);
std::filesystem::path NormalizePathForComparison(std::wstring_view path);
std::unordered_set<ULONG_PTR> GetProcessHandles(const DWORD pid);
bool CheckHandlesForFile(const DWORD pid, const std::unordered_set<ULONG_PTR>& currentHandles, const std::unordered_set<ULONG_PTR>& previousHandles, const std::filesystem::path& targetFile);
std::wstring GetProcessCommandLine(const DWORD pid);
bool HasForceWin32InFile(const std::filesystem::path& path);
bool IsWindows11();
bool IsGameDriveNvme(const std::filesystem::path& path);
bool IsUsingDirectStorage(const DWORD pid, const std::filesystem::path& dir);
std::vector<std::filesystem::path> GetGTAInstallDirectories();
bool RemoveTitleRgl(const std::filesystem::path& installPath);
void PauseExit();
bool IsRunningAsAdmin();
bool GrantModifyAccessToUsers(const std::filesystem::path& folderPath);