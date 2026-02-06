#include "ObjRef.h"

#include <cstring>
#include <stdexcept>

namespace
{
template <typename T>
T ReadValue(const std::vector<uint8_t>& data, size_t& offset)
{
    if (offset + sizeof(T) > data.size())
    {
        throw std::runtime_error("Buffer underflow");
    }

    T value;
    std::memcpy(&value, data.data() + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

template <typename T>
void WriteValue(std::vector<uint8_t>& data, T value)
{
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&value);
    data.insert(data.end(), ptr, ptr + sizeof(T));
}

GUID ReadGuid(const std::vector<uint8_t>& data, size_t& offset)
{
    if (offset + 16 > data.size())
    {
        throw std::runtime_error("Invalid GUID in OBJREF stream");
    }

    GUID guid;
    std::memcpy(&guid, data.data() + offset, 16);
    offset += 16;
    return guid;
}

void WriteGuid(std::vector<uint8_t>& data, const GUID& guid)
{
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&guid);
    data.insert(data.end(), ptr, ptr + sizeof(guid));
}

std::wstring ReadUtf16DoubleNull(const std::vector<uint8_t>& data, size_t& offset)
{
    std::wstring result;
    while (offset + sizeof(uint16_t) <= data.size())
    {
        uint16_t ch = ReadValue<uint16_t>(data, offset);
        if (ch == 0)
        {
            break;
        }
        result.push_back(static_cast<wchar_t>(ch));
    }

    if (offset + sizeof(uint16_t) <= data.size())
    {
        (void)ReadValue<uint16_t>(data, offset);
    }

    return result;
}

void WriteUtf16DoubleNull(std::vector<uint8_t>& data, const std::wstring& value)
{
    for (wchar_t ch : value)
    {
        WriteValue<uint16_t>(data, static_cast<uint16_t>(ch));
    }
    WriteValue<uint16_t>(data, 0);
    WriteValue<uint16_t>(data, 0);
}
} // namespace

ObjRef::ObjRef(const GUID& guid, std::unique_ptr<Standard> standardObjRef)
    : Guid(guid), StandardObjRef(std::move(standardObjRef))
{
}

ObjRef::ObjRef(const std::vector<uint8_t>& objRefBytes)
    : Guid(GUID_NULL)
{
    size_t offset = 0;

    uint32_t signature = ReadValue<uint32_t>(objRefBytes, offset);
    if (signature != Signature)
    {
        throw std::runtime_error("Does not look like an OBJREF stream");
    }

    uint32_t flags = ReadValue<uint32_t>(objRefBytes, offset);
    Guid = ReadGuid(objRefBytes, offset);

    if (static_cast<Type>(flags) == Type::Standard)
    {
        StandardObjRef = std::make_unique<Standard>(objRefBytes, offset);
    }
    else
    {
        // Align with C# behavior: ignore non-Standard types.
        StandardObjRef.reset();
    }
}

std::vector<uint8_t> ObjRef::GetBytes() const
{
    std::vector<uint8_t> result;

    WriteValue<uint32_t>(result, Signature);
    WriteValue<uint32_t>(result, static_cast<uint32_t>(Type::Standard));
    WriteGuid(result, Guid);

    if (StandardObjRef)
    {
        auto standardBytes = StandardObjRef->GetBytes();
        result.insert(result.end(), standardBytes.begin(), standardBytes.end());
    }

    return result;
}

ObjRef::SecurityBinding::SecurityBinding(uint16_t authnSvc, uint16_t authzSvc, const std::wstring& principalName)
    : AuthnSvc(authnSvc), AuthzSvc(authzSvc), PrincipalName(principalName)
{
}

ObjRef::SecurityBinding::SecurityBinding(const std::vector<uint8_t>& data, size_t& offset)
    : AuthnSvc(0), AuthzSvc(0)
{
    AuthnSvc = ReadValue<uint16_t>(data, offset);
    AuthzSvc = ReadValue<uint16_t>(data, offset);
    PrincipalName = ReadUtf16DoubleNull(data, offset);
}

std::vector<uint8_t> ObjRef::SecurityBinding::GetBytes() const
{
    std::vector<uint8_t> result;

    WriteValue<uint16_t>(result, AuthnSvc);
    WriteValue<uint16_t>(result, AuthzSvc);
    WriteUtf16DoubleNull(result, PrincipalName);

    return result;
}

ObjRef::StringBinding::StringBinding(TowerProtocol towerID, const std::wstring& networkAddress)
    : TowerID(towerID), NetworkAddress(networkAddress)
{
}

ObjRef::StringBinding::StringBinding(const std::vector<uint8_t>& data, size_t& offset)
    : TowerID(TowerProtocol::EPM_PROTOCOL_NULL)
{
    TowerID = static_cast<TowerProtocol>(ReadValue<uint16_t>(data, offset));
    NetworkAddress = ReadUtf16DoubleNull(data, offset);
}

std::vector<uint8_t> ObjRef::StringBinding::GetBytes() const
{
    std::vector<uint8_t> result;

    WriteValue<uint16_t>(result, static_cast<uint16_t>(TowerID));
    WriteUtf16DoubleNull(result, NetworkAddress);

    return result;
}

ObjRef::DualStringArray::DualStringArray(std::unique_ptr<StringBinding> stringBinding,
                                         std::unique_ptr<SecurityBinding> securityBinding)
    : NumEntries(0),
      SecurityOffset(0),
      stringBinding(std::move(stringBinding)),
      securityBinding(std::move(securityBinding))
{
    auto stringBindingBytes = this->stringBinding->GetBytes();
    auto securityBindingBytes = this->securityBinding->GetBytes();
    NumEntries = static_cast<uint16_t>((stringBindingBytes.size() + securityBindingBytes.size()) / 2);
    SecurityOffset = static_cast<uint16_t>(stringBindingBytes.size() / 2);
}

ObjRef::DualStringArray::DualStringArray(const std::vector<uint8_t>& data, size_t& offset)
    : NumEntries(0), SecurityOffset(0)
{
    NumEntries = ReadValue<uint16_t>(data, offset);
    SecurityOffset = ReadValue<uint16_t>(data, offset);

    stringBinding = std::make_unique<StringBinding>(data, offset);
    securityBinding = std::make_unique<SecurityBinding>(data, offset);
}

std::vector<uint8_t> ObjRef::DualStringArray::GetBytes() const
{
    std::vector<uint8_t> result;
    Save(result);
    return result;
}

void ObjRef::DualStringArray::Save(std::vector<uint8_t>& data) const
{
    auto stringBindingBytes = stringBinding->GetBytes();
    auto securityBindingBytes = securityBinding->GetBytes();

    uint16_t numEntries = static_cast<uint16_t>((stringBindingBytes.size() + securityBindingBytes.size()) / 2);
    uint16_t securityOffset = static_cast<uint16_t>(stringBindingBytes.size() / 2);

    WriteValue<uint16_t>(data, numEntries);
    WriteValue<uint16_t>(data, securityOffset);

    data.insert(data.end(), stringBindingBytes.begin(), stringBindingBytes.end());
    data.insert(data.end(), securityBindingBytes.begin(), securityBindingBytes.end());
}

ObjRef::Standard::Standard(uint32_t flags, uint32_t publicRefs, uint64_t oxid, uint64_t oid,
                           const GUID& ipid, std::unique_ptr<DualStringArray> dualStringArray)
    : Flags(flags),
      PublicRefs(publicRefs),
      OXID(oxid),
      OID(oid),
      IPID(ipid),
      dualStringArray(std::move(dualStringArray))
{
}

ObjRef::Standard::Standard(const std::vector<uint8_t>& data, size_t& offset)
    : Flags(0), PublicRefs(0), OXID(0), OID(0), IPID(GUID_NULL)
{
    Flags = ReadValue<uint32_t>(data, offset);
    PublicRefs = ReadValue<uint32_t>(data, offset);
    OXID = ReadValue<uint64_t>(data, offset);
    OID = ReadValue<uint64_t>(data, offset);
    IPID = ReadGuid(data, offset);

    dualStringArray = std::make_unique<DualStringArray>(data, offset);
}

std::vector<uint8_t> ObjRef::Standard::GetBytes() const
{
    std::vector<uint8_t> result;
    Save(result);
    return result;
}

void ObjRef::Standard::Save(std::vector<uint8_t>& data) const
{
    WriteValue<uint32_t>(data, Flags);
    WriteValue<uint32_t>(data, PublicRefs);
    WriteValue<uint64_t>(data, OXID);
    WriteValue<uint64_t>(data, OID);
    WriteGuid(data, IPID);

    if (dualStringArray)
    {
        dualStringArray->Save(data);
    }
}
