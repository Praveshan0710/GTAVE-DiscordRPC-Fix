#include "nt.h"
#include "utils.h"

bool Init()
{
    if (!InitNtApi())
    {
        std::wcerr << L"Failed to initialize ntdll functions.\n";
        PauseExit();
        return false;
    }

    if (!IsWindows11())
    {
        std::wcerr << L"This is intended for Windows 11.\n";
        PauseExit();
        return false;
    }

    auto [pid, path] = FindProcessAndPath(GTA::ProcessName);
    if (!pid) return true;

    std::wstring dir = GetDirectoryFromPath(path);

    if (IsUsingDirectStorage(pid, path, dir) && CheckHandlesForFile(pid, GetProcessHandles(pid), dir + L"\\" + GTA::FileName))
    {
        std::wcout << L"GTA V Enhanced is already running. Please restart the game.\n";
        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (!hProcess)
        {
            std::wcerr << L"Failed to wait for game to exit.\n";
            return false;
        }
        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
        return true;
    }
    return true;
}

int main()
{
    if (!Init()) return 1;

    for (const auto& path : GetGTAInstallPaths())
        RemoveTitleRgl(path);

    std::wcout << L"Ready. Launch GTA V Enhanced.\n";

    while (true)
    {
        auto [pid, exePath] = FindProcessAndPath(GTA::ProcessName);

        if (!pid)
        {
            Sleep(5000);
            continue;
        }

        std::wcout << L"Found GTA V Enhanced PID: " << pid << std::endl;

        std::wstring dir = GetDirectoryFromPath(exePath);

        if (!IsUsingDirectStorage(pid, exePath, dir))
        {
            PauseExit();
            return 1;
        }

        std::wstring targetFile = dir + L"\\" + GTA::FileName;
        std::wstring copiedFile = dir + GTA::UpdateDirName + L"\\" + GTA::FileName;

        auto previousHandles = GetProcessHandles(pid);
        bool detected = false, gameClosed = false;
        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pid);

        while (!detected)
        {
            if (WaitForSingleObject(hProcess, 1000) == WAIT_OBJECT_0)
            {
                gameClosed = true;
                break;
            }
            //std::wcout << L"Still waiting\n";

            auto currentHandles = GetProcessHandles(pid);

            std::set<ULONG_PTR> newHandles;

            for (const auto& h : currentHandles)
                if (!previousHandles.contains(h))
                    newHandles.insert(h);

            if (!newHandles.empty())
                detected = CheckHandlesForFile(pid, newHandles, targetFile);

            previousHandles = std::move(currentHandles);
        }

        if (gameClosed)
        {
            std::wcerr << L"GTA closed before opening title.rgl. Waiting for next game launch.\n";
            CloseHandle(hProcess);
            continue;
        }

        std::wcout << L"File handle to title.rgl opened.\n";

        CopyFileW(targetFile.c_str(), copiedFile.c_str(), FALSE);

        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);

        if (!DeleteFileW(copiedFile.c_str()))
            std::wcerr << L"Failed to remove " << copiedFile.c_str() << std::endl;

        std::wcout << L"Game closed. Waiting for next game launch.\n";
    }
}