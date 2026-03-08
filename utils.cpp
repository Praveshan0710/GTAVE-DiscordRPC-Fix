#include "nt.h"
#include "utils.h"
#include <tlhelp32.h>
#include <Aclapi.h>
#include <nvme.h>
#include <fstream>
#include <algorithm>
#include <iostream>
#pragma comment(lib, "Advapi32.lib")

namespace
{
    bool UsersHaveModifyAccess(PACL dacl, PSID usersSID)
    {
        if (!dacl) return false;

        DWORD modifyMask = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | SYNCHRONIZE;
        DWORD grantedMask = 0;

        for (DWORD i = 0; i < dacl->AceCount; ++i)
        {
            LPVOID ace = nullptr;
            if (!GetAce(dacl, i, &ace))
                continue;

            ACE_HEADER* header = (ACE_HEADER*)ace;

            if (header->AceType == ACCESS_DENIED_ACE_TYPE)
            {
                ACCESS_DENIED_ACE* denied = (ACCESS_DENIED_ACE*)ace;
                if (EqualSid(&denied->SidStart, usersSID) && (denied->Mask & modifyMask))
                    return false;
            }
            else if (header->AceType == ACCESS_ALLOWED_ACE_TYPE)
            {
                ACCESS_ALLOWED_ACE* allowed = (ACCESS_ALLOWED_ACE*)ace;
                if (EqualSid(&allowed->SidStart, usersSID))
                    grantedMask |= allowed->Mask;
            }
        }

        return (grantedMask & modifyMask) == modifyMask;
    }
}

std::optional<ProcessInfo> FindProcessIdAndDirectory(const wchar_t* processName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    
    if (!Process32FirstW(snap, &pe))
    {
        CloseHandle(snap);
        return {};
    }
    
    do
    {
        if (!_wcsicmp(pe.szExeFile, processName))
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
    
            if (hProcess)
            {
                wchar_t path[MAX_PATH];
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, path, &size))
                {
                    CloseHandle(hProcess);
                    CloseHandle(snap);
                    return ProcessInfo{ pe.th32ProcessID, std::filesystem::path(path).parent_path() };
                }
    
                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(snap, &pe));
    
    CloseHandle(snap);
    return {};
}

std::filesystem::path NormalizePathForComparison(std::wstring_view path)
{
    if (path.starts_with(L"\\\\?\\"))
        path = path.substr(4);
    return std::filesystem::path(path);
}

std::unordered_set<ULONG_PTR> GetProcessHandles(const DWORD pid)
{
    std::unordered_set<ULONG_PTR> result;
    ULONG size = 0x100000;
    std::vector<BYTE> buffer(size);
    ULONG retLen;
    NTSTATUS status;

    while ((status = g_Nt.NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, buffer.data(), size, &retLen)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        size = retLen + 0x10000;
        buffer.resize(size);
    }

    if (!NT_SUCCESS(status))
        return result;

    auto info = (SYSTEM_HANDLE_INFORMATION_EX*)buffer.data();
	result.reserve(info->NumberOfHandles);
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i)
    {
        if (info->Handles[i].UniqueProcessId == pid)
			result.insert(info->Handles[i].HandleValue);
    }
    return result;
}

bool CheckHandlesForFile(const DWORD pid, const std::unordered_set<ULONG_PTR>& currentHandles, const std::unordered_set<ULONG_PTR>& previousHandles, const std::filesystem::path& targetFile)
{
    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hProcess) return false;

    constexpr DWORD typeBufferSize = 512;

    for (const auto handleValue : currentHandles)
    {
        if (previousHandles.contains(handleValue)) continue;

        HANDLE dupHandle = nullptr;
        if (!DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(handleValue), GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) continue;

        BYTE typeBuffer[typeBufferSize];
        if (!NT_SUCCESS(g_Nt.NtQueryObject(dupHandle, ObjectTypeInformation, typeBuffer, typeBufferSize, nullptr)))
        {
            CloseHandle(dupHandle);
            continue;
        }

        auto* typeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(typeBuffer);
        std::wstring_view typeName(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR));
        if (typeName != L"File")
        {
            CloseHandle(dupHandle);
            continue;
        }

        wchar_t pathBuffer[MAX_PATH];
        DWORD len = GetFinalPathNameByHandleW(dupHandle, pathBuffer, _countof(pathBuffer), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (len == 0 || len >= _countof(pathBuffer))
        {
        	CloseHandle(dupHandle);
            continue;
        }
        CloseHandle(dupHandle);

        if (!_wcsicmp(NormalizePathForComparison(pathBuffer).c_str(), targetFile.c_str()))
        {
            CloseHandle(hProcess);
            return true;
        }
    }

    CloseHandle(hProcess);
    return false;
}

std::wstring GetProcessCommandLine(const DWORD pid)
{
    const auto hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return L"";

    ULONG len = 0;
    NTSTATUS st = g_Nt.NtQueryInformationProcess(hProc, (PROCESSINFOCLASS)60, nullptr, 0, &len);
    if (st != STATUS_INFO_LENGTH_MISMATCH || len == 0)
    {
        CloseHandle(hProc);
        return L"";
    }

    std::vector<BYTE> buf(len);
    st = g_Nt.NtQueryInformationProcess(hProc, (PROCESSINFOCLASS)60, buf.data(), len, &len);
    if (!NT_SUCCESS(st))
    {
        CloseHandle(hProc);
        return L"";
    }

    auto* pStr = reinterpret_cast<PUNICODE_STRING>(buf.data());
    if (pStr->Length == 0 || !pStr->Buffer)
    {
        CloseHandle(hProc);
        return L"";
    }

    std::wstring cmdline(pStr->Buffer, pStr->Length / sizeof(WCHAR));
    CloseHandle(hProc);
    return cmdline;
}

bool HasForceWin32InFile(const std::filesystem::path& path)
{
    std::wifstream file(path);
    if (!file.is_open()) return false;

    std::wstring line;

    while (std::getline(file, line))
    {
        if (!line.empty() && line.back() == L'\r')
            line.pop_back();

        line.erase(0, line.find_first_not_of(L" \t"));
        line.erase(line.find_last_not_of(L" \t") + 1);

        std::transform(line.begin(), line.end(), line.begin(), ::towlower);

        if (line == L"-forcewin32")
            return true;
    }

    return false;
}

bool IsWindows11()
{
    DWORD major = 0, minor = 0, build = 0;
    g_Nt.RtlGetNtVersionNumbers(&major, &minor, &build);
    return major == 10 && minor == 0 && (build & 0xFFFF) >= 22000;
}

bool IsGameDriveNvme(const std::filesystem::path& path)
{
    if (path.empty() || path.root_name().empty())
        return false;

    wchar_t volumePathName[MAX_PATH]{};
    if (!GetVolumePathNameW(path.c_str(), volumePathName, std::size(volumePathName)))
    {
        std::wcerr << L"GetVolumePathNameW failed. Error " << GetLastError() << std::endl;
        return false;
    }

    wchar_t volumeName[50]{};
    if (!GetVolumeNameForVolumeMountPointW(volumePathName, volumeName, std::size(volumeName)))
    {
        std::wcerr << L"GetVolumeNameForVolumeMountPointW failed. Error " << GetLastError() << std::endl;
        return false;
    }

    size_t len = wcslen(volumeName);
    if (len > 0 && volumeName[len - 1] == L'\\')
        volumeName[len - 1] = L'\0';

    const HANDLE hDevice = CreateFileW(volumeName, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"CreateFileW(" << volumeName << L") failed. Error " << GetLastError() << std::endl;
        return false;
    }

    const size_t bufferSize = FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters) + sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + NVME_MAX_LOG_SIZE;

    auto buffer = std::make_unique<uint8_t[]>(bufferSize);

    auto* query = reinterpret_cast<PSTORAGE_PROPERTY_QUERY>(buffer.get());
    query->PropertyId = StorageDeviceProtocolSpecificProperty;
    query->QueryType = PropertyStandardQuery;

    auto* protocolData = reinterpret_cast<PSTORAGE_PROTOCOL_SPECIFIC_DATA>(query->AdditionalParameters);
    protocolData->ProtocolType = ProtocolTypeNvme;
    protocolData->DataType = NVMeDataTypeIdentify;
    protocolData->ProtocolDataRequestValue = NVME_IDENTIFY_CNS_CONTROLLER;
    protocolData->ProtocolDataRequestSubValue = 0;
    protocolData->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    protocolData->ProtocolDataLength = NVME_MAX_LOG_SIZE;

    const BOOL success = DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, buffer.get(), static_cast<DWORD>(bufferSize), buffer.get(), static_cast<DWORD>(bufferSize), nullptr, nullptr);

    CloseHandle(hDevice);

    if (!success)
    {
        std::wcerr << L"DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY) failed. Error " << GetLastError() << std::endl;
        return false;
    }

    auto* dataDesc = reinterpret_cast<PSTORAGE_PROTOCOL_DATA_DESCRIPTOR>(buffer.get());
    if (dataDesc->Version != sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) || dataDesc->Size != sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR))
    {
        std::wcerr << L"Descriptor version/size mismatch\n";
        return false;
    }

    if (dataDesc->ProtocolSpecificData.ProtocolDataOffset < sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) || dataDesc->ProtocolSpecificData.ProtocolDataLength < sizeof(NVME_IDENTIFY_CONTROLLER_DATA))
    {
        std::wcerr << L"Protocol data offset/length too small\n";
        return false;
    }

    return true;
}

bool IsUsingDirectStorage(const DWORD pid, const std::filesystem::path& dir)
{
    if (!IsGameDriveNvme(dir))
    {
        std::wcerr << L"The game is not running on an NVMe SDD.\n";
        return false;
    }

    for (const auto& flagFile: GTA::FlagFiles)
    {
        const auto file = dir / flagFile;
        if (HasForceWin32InFile(file))
        {
            std::wcerr << L"Direct storage is disabled because -forcewin32 is in " << flagFile << std::endl;
            return false;
        }
    }

    std::wstring cmd = GetProcessCommandLine(pid);
    if (!cmd.empty())
    {
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::towlower);
        if (cmd.find(L"-forcewin32") != std::wstring::npos)
        {
            std::wcerr << L"Direct storage is disabled because -forcewin32 was passed as a launch argument.\n";
            return false;
        }
    }

    return true;
}

std::vector<std::filesystem::path> GetGTAInstallDirectories()
{
    std::vector<std::filesystem::path> paths;

    for (const auto* subkey : GTA::InstallRegistryKeys)
    {
        HKEY hKey{};
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        DWORD index = 0;
        wchar_t valueName[256];
        BYTE data[1024];

        while (true)
        {
            DWORD valueNameSize = _countof(valueName);
            DWORD dataSize = sizeof(data) - sizeof(wchar_t);
            DWORD type = 0;

            LONG result = RegEnumValueW(hKey, index++, valueName, &valueNameSize, nullptr, &type, data, &dataSize);

            if (result == ERROR_NO_MORE_ITEMS)
                break;
            if (result == ERROR_MORE_DATA)
            {
                std::wcerr << L"Registry value too large for buffer, skipping.\n";
                continue;
            }
            if (result != ERROR_SUCCESS || type != REG_SZ)
                continue;
            if (!wcsstr(valueName, L"InstallFolder"))
                continue;
            if (dataSize < sizeof(wchar_t))
                continue;

            reinterpret_cast<wchar_t*>(data)[dataSize / sizeof(wchar_t)] = L'\0';

            std::filesystem::path installPath(reinterpret_cast<wchar_t*>(data));
            const std::filesystem::path exePath = installPath / GTA::ProcessName;
            DWORD attr = GetFileAttributesW(exePath.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
                paths.push_back(std::move(installPath));
        }

        RegCloseKey(hKey);
    }

    if (paths.empty())
        std::wcerr << L"Could not find any game install paths in registry.\n";

    return paths;
}

bool RemoveTitleRgl(const std::filesystem::path& installPath)
{
	const std::filesystem::path file = installPath / GTA::UpdateDirName / GTA::TitleRgl;

    if (!DeleteFileW(file.c_str()))
    {
        switch (DWORD err = GetLastError())
        {
        case ERROR_FILE_NOT_FOUND:
            return true;

        case ERROR_ACCESS_DENIED:
            std::wcerr << L"Access denied: " << file << L"\n";
            return false;

        case ERROR_SHARING_VIOLATION:
            std::wcerr << L"File in use: " << file << L"\n";
            return false;

        default:
            std::wcerr << L"Delete failed: " << file << L"  error " << err << L"\n";
            return false;
        }
    }
    return true;
}

void PauseExit()
{
    std::wcout << L"Press enter to exit.\n";
    std::string dummy;
    std::getline(std::cin, dummy);
}

bool IsRunningAsAdmin()
{
    BOOL elevated = FALSE;

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        TOKEN_ELEVATION elevation{};
        DWORD size;

        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
            elevated = elevation.TokenIsElevated;

        CloseHandle(token);
    }

    return elevated;
}

bool GrantModifyAccessToUsers(const std::filesystem::path& folderPath)
{
    DWORD attr = GetFileAttributesW(folderPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        std::wcerr << L"Folder does not exist: " << folderPath << std::endl;
        return false;
    }

    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    PSID usersSID = sidBuffer;
    DWORD sidSize = sizeof(sidBuffer);
    if (!CreateWellKnownSid(WinBuiltinUsersSid, nullptr, usersSID, &sidSize))
    {
        std::wcerr << L"CreateWellKnownSid failed: " << GetLastError() << std::endl;
        return false;
    }

    PACL oldDACL = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD result = GetNamedSecurityInfoW(folderPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &oldDACL, nullptr, &sd);

    if (result != ERROR_SUCCESS)
    {
        std::wcerr << L"GetNamedSecurityInfoW failed: " << result << std::endl;
        return false;
    }

    if (UsersHaveModifyAccess(oldDACL, usersSID))
    {
        LocalFree(sd);
        return true;
    }

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | SYNCHRONIZE;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)usersSID;

    PACL newDACL = nullptr;
    result = SetEntriesInAclW(1, &ea, oldDACL, &newDACL);
    if (result != ERROR_SUCCESS)
    {
        LocalFree(sd);
        std::wcerr << L"SetEntriesInAclW failed: " << result << std::endl;
        return false;
    }

    result = SetNamedSecurityInfoW(std::wstring(folderPath).data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, newDACL, nullptr);

    bool success = (result == ERROR_SUCCESS);
    if (!success)
        std::wcerr << L"SetNamedSecurityInfoW failed: " << result << std::endl;

    if (newDACL) LocalFree(newDACL);
    if (sd) LocalFree(sd);
    return success;
}