#pragma once

#include <windows.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// TowerProtocol enum (matches C# values).
enum class TowerProtocol : uint16_t {
    EPM_PROTOCOL_DNET_NSP = 0x04,
    EPM_PROTOCOL_OSI_TP4 = 0x05,
    EPM_PROTOCOL_OSI_CLNS = 0x06,
    EPM_PROTOCOL_TCP = 0x07,
    EPM_PROTOCOL_UDP = 0x08,
    EPM_PROTOCOL_IP = 0x09,
    EPM_PROTOCOL_NCADG = 0x0a, /* Connectionless RPC */
    EPM_PROTOCOL_NCACN = 0x0b,
    EPM_PROTOCOL_NCALRPC = 0x0c, /* Local RPC */
    EPM_PROTOCOL_UUID = 0x0d,
    EPM_PROTOCOL_IPX = 0x0e,
    EPM_PROTOCOL_SMB = 0x0f,
    EPM_PROTOCOL_NAMED_PIPE = 0x10,
    EPM_PROTOCOL_NETBIOS = 0x11,
    EPM_PROTOCOL_NETBEUI = 0x12,
    EPM_PROTOCOL_SPX = 0x13,
    EPM_PROTOCOL_NB_IPX = 0x14, /* NetBIOS over IPX */
    EPM_PROTOCOL_DSP = 0x16, /* AppleTalk Data Stream Protocol */
    EPM_PROTOCOL_DDP = 0x17, /* AppleTalk Data Datagram Protocol */
    EPM_PROTOCOL_APPLETALK = 0x18, /* AppleTalk */
    EPM_PROTOCOL_VINES_SPP = 0x1a,
    EPM_PROTOCOL_VINES_IPC = 0x1b, /* Inter Process Communication */
    EPM_PROTOCOL_STREETTALK = 0x1c, /* Vines Streettalk */
    EPM_PROTOCOL_HTTP = 0x1f,
    EPM_PROTOCOL_UNIX_DS = 0x20, /* Unix domain socket */
    EPM_PROTOCOL_NULL = 0x21
};

class ObjRef {
public:
    class Standard;

    enum class Type : uint32_t {
        Standard = 0x1,
        Handler = 0x2,
        Custom = 0x4
    };

    static const uint32_t Signature = 0x574f454d; // "MEOW" in little endian

    GUID Guid;
    std::unique_ptr<Standard> StandardObjRef;

    ObjRef(const GUID& guid, std::unique_ptr<Standard> standardObjRef);
    ObjRef(const std::vector<uint8_t>& objRefBytes);

    std::vector<uint8_t> GetBytes() const;

    class SecurityBinding {
    public:
        uint16_t AuthnSvc;
        uint16_t AuthzSvc;
        std::wstring PrincipalName;

        SecurityBinding(uint16_t authnSvc, uint16_t authzSvc, const std::wstring& principalName);
        SecurityBinding(const std::vector<uint8_t>& data, size_t& offset);

        std::vector<uint8_t> GetBytes() const;
    };

    class StringBinding {
    public:
        TowerProtocol TowerID;
        std::wstring NetworkAddress;

        StringBinding(TowerProtocol towerID, const std::wstring& networkAddress);
        StringBinding(const std::vector<uint8_t>& data, size_t& offset);

        std::vector<uint8_t> GetBytes() const;
    };

    class DualStringArray {
    public:
        uint16_t NumEntries;
        uint16_t SecurityOffset;
        std::unique_ptr<StringBinding> stringBinding;
        std::unique_ptr<SecurityBinding> securityBinding;

        DualStringArray(std::unique_ptr<StringBinding> stringBinding,
                        std::unique_ptr<SecurityBinding> securityBinding);
        DualStringArray(const std::vector<uint8_t>& data, size_t& offset);

        std::vector<uint8_t> GetBytes() const;
        void Save(std::vector<uint8_t>& data) const;
    };

    class Standard {
    public:
        uint32_t Flags;
        uint32_t PublicRefs;
        uint64_t OXID;
        uint64_t OID;
        GUID IPID;
        std::unique_ptr<DualStringArray> dualStringArray;

        Standard(uint32_t flags, uint32_t publicRefs, uint64_t oxid, uint64_t oid,
                 const GUID& ipid, std::unique_ptr<DualStringArray> dualStringArray);
        Standard(const std::vector<uint8_t>& data, size_t& offset);

        std::vector<uint8_t> GetBytes() const;
        void Save(std::vector<uint8_t>& data) const;
    };
};
