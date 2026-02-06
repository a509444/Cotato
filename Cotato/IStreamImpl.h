#pragma once

#include <objidl.h>
#include <cstdint>
#include <vector>

// Simple in-memory IStream implementation (subset) used for CoUnmarshalInterface.
class IStreamImpl final : public IStream
{
public:
    explicit IStreamImpl(const std::vector<uint8_t>& data);
    explicit IStreamImpl(std::vector<uint8_t>&& data);

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
    ULONG STDMETHODCALLTYPE AddRef() override;
    ULONG STDMETHODCALLTYPE Release() override;

    // IStream
    HRESULT STDMETHODCALLTYPE Read(void* pv, ULONG cb, ULONG* pcbRead) override;
    HRESULT STDMETHODCALLTYPE Write(const void* pv, ULONG cb, ULONG* pcbWritten) override;
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER* plibNewPosition) override;
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER libNewSize) override;
    HRESULT STDMETHODCALLTYPE CopyTo(IStream* pstm, ULARGE_INTEGER cb, ULARGE_INTEGER* pcbRead, ULARGE_INTEGER* pcbWritten) override;
    HRESULT STDMETHODCALLTYPE Commit(DWORD grfCommitFlags) override;
    HRESULT STDMETHODCALLTYPE Revert() override;
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) override;
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) override;
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* pstatstg, DWORD grfStatFlag) override;
    HRESULT STDMETHODCALLTYPE Clone(IStream** ppstm) override;

private:
    ~IStreamImpl() = default;

    ULONG refCount;
    std::vector<uint8_t> buffer;
    size_t position;
};
