#pragma once

#include <objidl.h>
#include <string>
#include <vector>

#include "ObjRef.h"
#include "UnmarshalDCOM.h"
#include "potato.h"

class GodPotatoUnmarshalTrigger
{
public:
    explicit GodPotatoUnmarshalTrigger(GodPotatoContext* context);
    ~GodPotatoUnmarshalTrigger();

    HRESULT Trigger();

private:
    static const GUID IID_IUnknown_Guid;
    static const wchar_t* const Binding;
    static const TowerProtocol TowerProto;

    GodPotatoContext* godPotatoContext;
    IUnknown* pIUnknown;
    IBindCtx* bindCtx;
    IMoniker* moniker;
};
