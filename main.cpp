#include "nt.h"
#include "utils.h"
#include <iostream>

bool Init()
{
    if (!InitNtApi())
    {
        std::wcerr << L"Failed to initialize ntdll functions.\n";
        return false;
    }

    if (!IsWindows11())
    {
        std::wcerr << L"This is intended for Windows 11.\n";
        return false;
    }

	const auto info = FindProcessIdAndDirectory(GTA::ProcessName);
    if (!info) return true;

    if (!IsUsingDirectStorage(info->pid, info->directory)) return false;

    if (CheckHandlesForFile(info->pid, GetProcessHandles(info->pid), {}, info->directory / GTA::TitleRgl))
    {
        std::wcout << L"GTA V Enhanced is already running. Please restart the game.\n";
        const auto hProcess = OpenProcess(SYNCHRONIZE, FALSE, info->pid);
        if (!hProcess)
        {
            std::wcerr << L"Failed to wait for game to exit.\n";
            return false;
        }
        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
    }
    return true;
}

int main()
{
    if (!Init())
    {
        PauseExit();
        return 1;
    }
    const bool isAdmin = IsRunningAsAdmin();
    for (const auto& gameInstallDir : GetGTAInstallDirectories())
    {
        if (isAdmin) GrantModifyAccessToUsers(gameInstallDir);
        RemoveTitleRgl(gameInstallDir);
    }

    std::wcout << L"Ready. Launch GTA V Enhanced.\n";

    while (true)
    {
        const auto info = FindProcessIdAndDirectory(GTA::ProcessName);

        if (!info)
        {
            Sleep(5000);
            continue;
        }

        std::wcout << L"Found GTA V Enhanced PID: " << info->pid << std::endl;

        if (!IsUsingDirectStorage(info->pid, info->directory))
        {
            PauseExit();
            return 1;
        }

		const auto targetFile = info->directory / GTA::TitleRgl;
		const auto copiedFile = info->directory / GTA::UpdateDirName / GTA::TitleRgl;

        auto previousHandles = GetProcessHandles(info->pid);
        bool detected = false, gameClosed = false;
        const auto hProcess = OpenProcess(SYNCHRONIZE, FALSE, info->pid);

        while (!detected)
        {
            if (WaitForSingleObject(hProcess, 1000) == WAIT_OBJECT_0)
            {
                gameClosed = true;
                break;
            }

            auto currentHandles = GetProcessHandles(info->pid);
            detected = CheckHandlesForFile(info->pid, currentHandles, previousHandles, targetFile);
            previousHandles = std::move(currentHandles);
        }

        if (gameClosed)
        {
            std::wcerr << L"GTA V Enhanced closed before initializing. Waiting for next game launch.\n";
            CloseHandle(hProcess);
            continue;
        }

        if (isAdmin) GrantModifyAccessToUsers(info->directory);

        if (!CopyFileW(targetFile.c_str(), copiedFile.c_str(), FALSE))
        {
            const auto err = GetLastError();
            if (err == ERROR_ACCESS_DENIED)
            {
                std::wcerr << L"You don't have permission to modify the game directory.\n"
                    << L"Please start this application as an administator at least once or get permission to modify " << info->directory << std::endl;
                PauseExit();
                return 1;
            }
            else
            {
                std::wcerr << L"CopyFileW failed. Error: " << err << std::endl;
                PauseExit();
                return 1;
            }
        }

        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
        RemoveTitleRgl(info->directory);

        std::wcout << L"Game closed. Waiting for next game launch.\n";
    }
}