#pragma once
#include <Windows.h>
#include <shellapi.h>
#pragma comment(lib, "Shell32.lib")

constexpr UINT WM_TRAY = WM_APP + 1;
constexpr UINT IDM_EXIT = 1001;

bool InitTray(HINSTANCE hInstance);
void RemoveTray();
void ShowTrayNotification(const wchar_t* title, const wchar_t* message, DWORD infoFlags = NIIF_INFO);