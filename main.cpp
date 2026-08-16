#include "tray.h"
#include "worker.h"
#include <Windows.h>
#include <thread>

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int)
{
    if (!InitTray(hInstance))
        return 1;

    std::thread workerThread(RunWorker);
    workerThread.detach();

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    RemoveTray();
    return 0;
}