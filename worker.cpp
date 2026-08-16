#include "worker.h"
#include "tray.h"
#include "nt.h"
#include "utils.h"


void RunWorker()
{
    if (!InitNtApi())
    {
        ShowTrayNotification(L"Error", L"Failed to initialize ntdll functions.", NIIF_ERROR);
        return;
    }

    if (!IsWindows11())
    {
        ShowTrayNotification(L"Error", L"This is intended for Windows 11.", NIIF_ERROR);
        return;
    }

    const auto info = FindProcessIdAndDirectory(GTA::ProcessName);
    if (info)
    {
        if (!IsUsingDirectStorage(info->pid, info->directory))
        {
            ShowTrayNotification(L"Error", L"DirectStorage is not in use.", NIIF_ERROR);
            return;
        }

        if (CheckHandlesForFile(info->pid, GetProcessHandles(info->pid), {}, info->directory / GTA::TitleRgl))
        {
            ShowTrayNotification(L"Warning", L"GTA V Enhanced is already running. Please restart the game.", NIIF_WARNING);
            const auto hProcess = OpenProcess(SYNCHRONIZE, FALSE, info->pid);
            WaitForSingleObject(hProcess, INFINITE);
            CloseHandle(hProcess);
        }
    }

    const bool isAdmin = IsRunningAsAdmin();
    for (const auto& gameInstallDir : GetGTAInstallDirectories())
    {
        if (isAdmin) GrantModifyAccessToUsers(gameInstallDir);
        RemoveTitleRgl(gameInstallDir);
    }

    ShowTrayNotification(L"Ready", L"Waiting for GTA V Enhanced to launch.", NIIF_INFO);

    while (true)
    {
        const auto info = FindProcessIdAndDirectory(GTA::ProcessName);

        if (!info)
        {
            Sleep(5000);
            continue;
        }

        ShowTrayNotification(L"Game launched", L"Game detected, monitoring...", NIIF_INFO);

        if (!IsUsingDirectStorage(info->pid, info->directory))
        {
            ShowTrayNotification(L"Error", L"DirectStorage is not in use.", NIIF_ERROR);
            return;
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
            ShowTrayNotification(L"Warning", L"GTA V Enhanced closed before initializing.", NIIF_WARNING);
            CloseHandle(hProcess);
            continue;
        }

        if (isAdmin) GrantModifyAccessToUsers(info->directory);

        if (!CopyFileW(targetFile.c_str(), copiedFile.c_str(), FALSE))
        {
            const auto err = GetLastError();
            if (err == ERROR_ACCESS_DENIED)
                ShowTrayNotification(L"Error", L"Please run as administrator at least once to grant modify access.", NIIF_ERROR);
            else
                ShowTrayNotification(L"Error", L"Failed to copy title.rgl.", NIIF_ERROR);
            CloseHandle(hProcess);
            return;
        }

        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
        RemoveTitleRgl(info->directory);

        ShowTrayNotification(L"Game closed", L"Waiting for next launch.", NIIF_INFO);
    }
}