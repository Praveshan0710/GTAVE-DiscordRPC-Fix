#include "nt.h"
#include "utils.h"

std::pair<DWORD, std::wstring> FindProcessAndPath(const std::wstring_view processName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe))
    {
        CloseHandle(snap);
        return { 0, L"" };
    }

    do
    {
        if (!_wcsicmp(pe.szExeFile, processName.data()))
        {
            HANDLE hProcess =OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);

            if (hProcess)
            {
                wchar_t path[MAX_PATH];
                DWORD size = MAX_PATH;

                if (QueryFullProcessImageNameW(hProcess, 0, path, &size))
                {
                    CloseHandle(hProcess);
                    CloseHandle(snap);
                    return { pe.th32ProcessID, path };
                }

                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return { 0, L"" };
}

std::wstring GetDirectoryFromPath(const std::wstring& fullPath)
{
    size_t pos = fullPath.find_last_of(L"\\");
    if (pos == std::wstring::npos) return L"";
    return fullPath.substr(0, pos);
}

std::wstring NormalizePathForComparison(std::wstring path)
{
    if (path.starts_with(L"\\\\?\\"))
        path = path.substr(4);
    return path;
}

std::set<ULONG_PTR> GetProcessHandles(DWORD pid)
{
    std::set<ULONG_PTR> result;

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

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++)
    {
        auto& h = info->Handles[i];

        if (h.UniqueProcessId == pid)
            result.insert(h.HandleValue);
    }
    return result;
}

bool CheckHandlesForFile(DWORD pid, const std::set<ULONG_PTR>& newHandles, const std::wstring_view targetFile)
{
    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);

    if (!hProcess)
        return false;

    for (auto handleValue : newHandles)
    {
        HANDLE dupHandle;

        if (!DuplicateHandle(hProcess, (HANDLE)handleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        BYTE typeBuffer[512];

        if (!NT_SUCCESS(g_Nt.NtQueryObject(dupHandle, ObjectTypeInformation, typeBuffer, sizeof(typeBuffer), nullptr)))
        {
            CloseHandle(dupHandle);
            continue;
        }

        auto typeInfo = (POBJECT_TYPE_INFORMATION)typeBuffer;

        std::wstring typeName(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR));

        if (typeName != L"File")
        {
            CloseHandle(dupHandle);
            continue;
        }

        wchar_t path[MAX_PATH];

        DWORD len = GetFinalPathNameByHandleW(dupHandle, path, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);

        if (len && len < MAX_PATH)
        {
            std::wstring handleFile = NormalizePathForComparison(path);

            if (!_wcsicmp(handleFile.c_str(), targetFile.data()))
            {
                CloseHandle(dupHandle);
                CloseHandle(hProcess);
                return true;
            }
        }

        CloseHandle(dupHandle);
    }

    CloseHandle(hProcess);
    return false;
}

std::wstring GetProcessCommandLine(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
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

bool HasForceWin32InFile(const std::wstring& dir, const std::wstring_view filename)
{
    std::wstring path = dir + L"\\" + filename.data();

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

bool IsGameDriveNvme(const std::wstring& exePath)
{
    if (exePath.empty() || exePath.length() < 3 || exePath[1] != L':')
    {
        return false;
    }

    wchar_t volumePathName[MAX_PATH]{};
    if (!GetVolumePathNameW(exePath.c_str(), volumePathName, std::size(volumePathName)))
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
    {
        volumeName[len - 1] = L'\0';
    }

    HANDLE hDevice = CreateFileW(volumeName, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"CreateFileW(" << volumeName << L") failed. Error " << GetLastError() << std::endl;
        return false;
    }
    constexpr size_t bufferSize = FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters)
        + sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA)
        + NVME_MAX_LOG_SIZE;

    auto buffer = std::make_unique_for_overwrite<uint8_t[]>(bufferSize);
    auto* query = reinterpret_cast<PSTORAGE_PROPERTY_QUERY>(buffer.get());

    query->PropertyId = StorageAdapterProtocolSpecificProperty;
    query->QueryType = PropertyStandardQuery;

    auto* protocolData = reinterpret_cast<PSTORAGE_PROTOCOL_SPECIFIC_DATA>(query->AdditionalParameters);
    protocolData->ProtocolType = ProtocolTypeNvme;
    protocolData->DataType = NVMeDataTypeIdentify;
    protocolData->ProtocolDataRequestValue = NVME_IDENTIFY_CNS_CONTROLLER;
    protocolData->ProtocolDataRequestSubValue = 0;
    protocolData->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    protocolData->ProtocolDataLength = NVME_MAX_LOG_SIZE;

    BOOL success = DeviceIoControl(hDevice,
        IOCTL_STORAGE_QUERY_PROPERTY,
        buffer.get(),
        static_cast<DWORD>(bufferSize),
        buffer.get(),
        static_cast<DWORD>(bufferSize),
        nullptr,
        nullptr);

    CloseHandle(hDevice);

    if (!success)
    {
        std::wcerr << L"DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY) failed. Error " << GetLastError() << std::endl;
        return false;
    }

    auto* dataDesc = reinterpret_cast<PSTORAGE_PROTOCOL_DATA_DESCRIPTOR>(buffer.get());

    if (dataDesc->Version != sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) || dataDesc->Size != sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR))
    {
        std::wcerr << L"Descriptor version/size mismatch" << std::endl;
        return false;
    }

    if (dataDesc->ProtocolSpecificData.ProtocolDataOffset < sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) || dataDesc->ProtocolSpecificData.ProtocolDataLength < sizeof(NVME_IDENTIFY_CONTROLLER_DATA))
    {
        std::wcerr << L"Protocol data offset/length too small" << std::endl;
        return false;
    }

    auto* identify = reinterpret_cast<PNVME_IDENTIFY_CONTROLLER_DATA>(reinterpret_cast<uint8_t*>(&dataDesc->ProtocolSpecificData) + dataDesc->ProtocolSpecificData.ProtocolDataOffset);

    bool looksLikeNvme = (identify->VID != 0 && identify->NN != 0);

    if (looksLikeNvme)
    {
        std::wcout << L"Game drive appears to be NVMe (VID=0x" << std::hex << identify->VID
            << L", NN=" << std::dec << identify->NN << L")" << std::endl;
    }
    else
    {
        std::wcerr << L"Game drive is not detected as NVMe" << std::endl;
    }

    return looksLikeNvme;
}

bool IsUsingDirectStorage(DWORD pid, const std::wstring& exePath, const std::wstring& dir)
{
    if (!IsGameDriveNvme(exePath))
    {
        std::wcerr << L"The game is not running on an NVMe SDD.\n";
        return false;
    }

    for (const auto& file: GTA::FlagFiles)
    {
        if (HasForceWin32InFile(dir, file))
        {
            std::wcerr << L"Direct storage is disabled because -forcewin32 is in " << file << std::endl;
            return false;
        }
    }

    std::wstring cmd = GetProcessCommandLine(pid);
    if (!cmd.empty())
    {
        std::wstring lowerCmd = cmd;
        std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);
        if (lowerCmd.find(L"-forcewin32") != std::wstring::npos)
        {
            std::wcerr << L"Direct storage is disabled because -forcewin32 was passed as a launch argument.\n";
            return false;
        }
    }

    return true;
}

std::vector<std::wstring> GetGTAInstallPaths()
{
    std::vector<std::wstring> paths;

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
            DWORD dataSize = sizeof(data);
            DWORD type = 0;

            LONG result = RegEnumValueW(hKey, index++, valueName, &valueNameSize, nullptr, &type, data, &dataSize);

            if (result == ERROR_NO_MORE_ITEMS) break;

            if (result != ERROR_SUCCESS || type != REG_SZ) continue;

            std::wstring name(valueName);

            if (name.find(L"InstallFolder") == std::wstring::npos)
                continue;

            std::wstring installPath(reinterpret_cast<wchar_t*>(data));

            while (!installPath.empty() && (installPath.back() == L'\\' || installPath.back() == L'/'))
                installPath.pop_back();

            std::wstring exePath = installPath + L"\\" + GTA::ProcessName;

            DWORD attr = GetFileAttributesW(exePath.c_str());

            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
                paths.push_back(std::move(installPath));
        }
        RegCloseKey(hKey);
    }
    if (paths.empty())
        std::wcerr << "Could find any game install paths by registry.\n";

    return paths;
}

bool RemoveTitleRgl(const std::wstring& installPath)
{
    std::wstring file = installPath + L"\\update\\x64\\title.rgl";

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

bool GrantFullControlToUsers(const std::wstring& folderPath)
{
    DWORD attr = GetFileAttributesW(folderPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        std::wcerr << L"Folder does not exist: " << folderPath << std::endl;
        return false;
    }

    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pOldDACL = nullptr;

    if (GetNamedSecurityInfoW(folderPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &pOldDACL, nullptr, &pSD) != ERROR_SUCCESS)
    {
        std::wcerr << L"Failed to get DACL for folder.\n";
        return false;
    }

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)L"Users";

    PACL pNewDACL = nullptr;
    if (SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL) != ERROR_SUCCESS)
    {
        if (pSD) LocalFree(pSD);
        std::wcerr << L"Failed to create new ACL.\n";
        return false;
    }

    bool success = SetNamedSecurityInfoW((LPWSTR)folderPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDACL, nullptr) == ERROR_SUCCESS;

    if (pNewDACL) LocalFree(pNewDACL);
    if (pSD) LocalFree(pSD);

    return success;
}