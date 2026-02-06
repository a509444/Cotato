#define INITGUID
#include <initguid.h>
#include "IStreamImpl.h"

#include <algorithm>
#include <cstring>

IStreamImpl::IStreamImpl(const std::vector<uint8_t>& data)
    : refCount(1), buffer(data), position(0)
{
}

IStreamImpl::IStreamImpl(std::vector<uint8_t>&& data)
    : refCount(1), buffer(std::move(data)), position(0)
{
}

HRESULT STDMETHODCALLTYPE IStreamImpl::QueryInterface(REFIID riid, void** ppvObject)
{
    if (!ppvObject)
    {
        return E_POINTER;
    }

    if (riid == IID_IUnknown || riid == IID_IStream)
    {
        *ppvObject = static_cast<IStream*>(this);
        AddRef();
        return S_OK;
    }

    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE IStreamImpl::AddRef()
{
    return ++refCount;
}

ULONG STDMETHODCALLTYPE IStreamImpl::Release()
{
    ULONG next = --refCount;
    if (next == 0)
    {
        delete this;
    }
    return next;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Read(void* pv, ULONG cb, ULONG* pcbRead)
{
    if (!pv)
    {
        return E_POINTER;
    }

    size_t remaining = buffer.size() - position;
    size_t toRead = std::min<size_t>(cb, remaining);
    if (toRead > 0)
    {
        std::memcpy(pv, buffer.data() + position, toRead);
        position += toRead;
    }

    if (pcbRead)
    {
        *pcbRead = static_cast<ULONG>(toRead);
    }

    return (toRead == cb) ? S_OK : S_FALSE;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Write(const void* pv, ULONG cb, ULONG* pcbWritten)
{
    if (!pv)
    {
        return E_POINTER;
    }

    if (position + cb > buffer.size())
    {
        buffer.resize(position + cb);
    }

    std::memcpy(buffer.data() + position, pv, cb);
    position += cb;

    if (pcbWritten)
    {
        *pcbWritten = cb;
    }

    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Seek(LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER* plibNewPosition)
{
    int64_t newPos = 0;
    switch (dwOrigin)
    {
    case STREAM_SEEK_SET:
        newPos = dlibMove.QuadPart;
        break;
    case STREAM_SEEK_CUR:
        newPos = static_cast<int64_t>(position) + dlibMove.QuadPart;
        break;
    case STREAM_SEEK_END:
        newPos = static_cast<int64_t>(buffer.size()) + dlibMove.QuadPart;
        break;
    default:
        return STG_E_INVALIDFUNCTION;
    }

    if (newPos < 0)
    {
        return STG_E_INVALIDFUNCTION;
    }

    position = static_cast<size_t>(newPos);
    if (plibNewPosition)
    {
        plibNewPosition->QuadPart = position;
    }

    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::SetSize(ULARGE_INTEGER libNewSize)
{
    buffer.resize(static_cast<size_t>(libNewSize.QuadPart));
    if (position > buffer.size())
    {
        position = buffer.size();
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::CopyTo(IStream* /*pstm*/, ULARGE_INTEGER /*cb*/, ULARGE_INTEGER* /*pcbRead*/, ULARGE_INTEGER* /*pcbWritten*/)
{
    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Commit(DWORD /*grfCommitFlags*/)
{
    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Revert()
{
    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::LockRegion(ULARGE_INTEGER /*libOffset*/, ULARGE_INTEGER /*cb*/, DWORD /*dwLockType*/)
{
    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::UnlockRegion(ULARGE_INTEGER /*libOffset*/, ULARGE_INTEGER /*cb*/, DWORD /*dwLockType*/)
{
    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Stat(STATSTG* pstatstg, DWORD /*grfStatFlag*/)
{
    if (!pstatstg)
    {
        return E_POINTER;
    }

    std::memset(pstatstg, 0, sizeof(STATSTG));
    pstatstg->cbSize.QuadPart = static_cast<ULONGLONG>(buffer.size());
    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Clone(IStream** /*ppstm*/)
{
    return E_NOTIMPL;
}


