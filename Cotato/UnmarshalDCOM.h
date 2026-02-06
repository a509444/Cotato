#pragma once

#include <objidl.h>
#include <cstdint>
#include <vector>

class UnmarshalDCOM
{
public:
    static HRESULT UnmarshalObject(IStream* stream, REFIID iid, void** ppv);
    static HRESULT UnmarshalObject(const std::vector<uint8_t>& objref, void** ppv);
};
