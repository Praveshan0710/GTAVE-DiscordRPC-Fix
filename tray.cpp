#include "tray.h"
#include "resource.h"
#include <iostream>

static HWND g_hWnd = nullptr;
static NOTIFYICONDATAW g_nid{};

LRESULT CALLBACK TrayWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_TRAY:
            if (lParam == WM_RBUTTONUP)
            {
                POINT pt{};
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, IDM_EXIT, L"Exit");
                SetForegroundWindow(hWnd);
                TrackPopupMenu(hMenu, TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, nullptr);
                DestroyMenu(hMenu);
            }
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == IDM_EXIT)
                PostQuitMessage(0);
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

bool InitTray(HINSTANCE hInstance)
{
    WNDCLASSEXW wx{};
    wx.cbSize = sizeof(wx);
    wx.lpfnWndProc = TrayWndProc;
    wx.hInstance = hInstance;
    wx.lpszClassName = L"GTAVEDiscordFixerUpperTray";
    if (!RegisterClassExW(&wx)) return false;

    g_hWnd = CreateWindowExW(0, L"GTAVEDiscordFixerUpperTray", L"GTAVEDiscordFixerUpper", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, hInstance, nullptr);
    if (!g_hWnd) return false;

    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hWnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon = reinterpret_cast<HICON>(LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR));
    wcscpy_s(g_nid.szTip, L"GTAVEDiscordFixerUpper");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
    return true;
}

void RemoveTray()
{
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    if (g_hWnd) DestroyWindow(g_hWnd);
}

void ShowTrayNotification(const wchar_t* title, const wchar_t* message, DWORD infoFlags)
{
    g_nid.uFlags |= NIF_INFO;
    wcscpy_s(g_nid.szInfoTitle, title);
    wcscpy_s(g_nid.szInfo, message);
    g_nid.dwInfoFlags = NIIF_NOSOUND | infoFlags;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}