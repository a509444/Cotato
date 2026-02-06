#include "UnmarshalDCOM.h"
#include "IStreamImpl.h"
#include "log.h"

#include <objbase.h>
#include <iostream>

namespace
{
const GUID IID_IUnknown_Guid = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
}

HRESULT UnmarshalDCOM::UnmarshalObject(IStream* stream, REFIID iid, void** ppv)
{
    if (!stream || !ppv)
    {
        return E_POINTER;
    }

    LOG_INFO_STREAM << "[*] CoUnmarshalInterface begin (IStream)" << std::endl;
    HRESULT hr = CoUnmarshalInterface(stream, iid, ppv);
    LOG_INFO_STREAM << "[*] CoUnmarshalInterface end (IStream) hr=0x" << std::hex << hr << std::dec << std::endl;
    if (FAILED(hr))
    {
        LOG_ERROR_STREAM << "[!] CoUnmarshalInterface failed: 0x" << std::hex << hr << std::dec << std::endl;
    }
    return hr;
}

HRESULT UnmarshalDCOM::UnmarshalObject(const std::vector<uint8_t>& objref, void** ppv)
{
    if (!ppv)
    {
        return E_POINTER;
    }

    IStreamImpl* stream = new IStreamImpl(objref);
    LOG_INFO_STREAM << "[*] CoUnmarshalInterface begin (IID_IUnknown) bytes=" << objref.size() << std::endl;
    HRESULT hr = CoUnmarshalInterface(stream, IID_IUnknown_Guid, ppv);
    LOG_INFO_STREAM << "[*] CoUnmarshalInterface end (IID_IUnknown) hr=0x" << std::hex << hr << std::dec << std::endl;
    if (FAILED(hr))
    {
        LOG_ERROR_STREAM << "[!] CoUnmarshalInterface(IID_IUnknown) failed: 0x" << std::hex << hr << std::dec << std::endl;
    }
    stream->Release();
    return hr;
}




