// Copyright 2020 The Dawn Authors
// Copyright 2022 The GPGMM Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "gpgmm/d3d12/HeapD3D12.h"

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm::d3d12 {

    namespace {

        // Returns the resource heap flags or E_INVALIDARG, when the memory type doesn't allow
        // resources.
        HRESULT GetResourceHeapFlags(ComPtr<ID3D12Pageable> pageable, D3D12_HEAP_FLAGS* heapFlags) {
            ComPtr<ID3D12Heap> heap;
            if (SUCCEEDED(pageable.As(&heap))) {
                *heapFlags = heap->GetDesc().Flags;
                return S_OK;
            }

            ComPtr<ID3D12Resource> committedResource;
            if (SUCCEEDED(pageable.As(&committedResource))) {
                ReturnIfFailed(committedResource->GetHeapProperties(nullptr, heapFlags));
                return S_OK;
            }

            return E_INVALIDARG;
        }
    }  // namespace

    HEAP_FLAGS GetHeapFlags(D3D12_HEAP_FLAGS heapFlags, bool alwaysCreatedInBudget) {
        if (alwaysCreatedInBudget) {
            return HEAP_FLAG_ALWAYS_IN_BUDGET | HEAP_FLAG_ALWAYS_IN_RESIDENCY;
        }

        return HEAP_FLAG_ALWAYS_IN_RESIDENCY;
    }

    HRESULT CreateHeap(const HEAP_DESC& descriptor,
                       IResidencyManager* const pResidencyManager,
                       CreateHeapFn createHeapFn,
                       void* pCreateHeapContext,
                       IHeap** ppHeapOut) {
        return Heap::CreateHeap(descriptor, pResidencyManager, createHeapFn, pCreateHeapContext,
                                ppHeapOut);
    }

    // static
    HRESULT Heap::CreateHeap(const HEAP_DESC& descriptor,
                             IResidencyManager* const pResidencyManager,
                             CreateHeapFn createHeapFn,
                             void* pCreateHeapContext,
                             IHeap** ppHeapOut) {
        ReturnIfNullptr(pCreateHeapContext);

        const bool isResidencyDisabled = (pResidencyManager == nullptr);

        ResidencyManager* residencyManager = static_cast<ResidencyManager*>(pResidencyManager);

        // Ensure enough budget exists before creating the heap to avoid an out-of-memory error.
        if (!isResidencyDisabled && (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET)) {
            if (FAILED(residencyManager->EnsureInBudget(descriptor.SizeInBytes,
                                                        descriptor.MemorySegmentGroup))) {
                DXGI_QUERY_VIDEO_MEMORY_INFO currentVideoInfo = {};
                if (SUCCEEDED(residencyManager->QueryVideoMemoryInfo(descriptor.MemorySegmentGroup,
                                                                     &currentVideoInfo))) {
                    gpgmm::ErrorLog(MessageId::kBudgetExceeded)
                        << "Unable to create heap because not enough budget exists ("
                        << GPGMM_BYTES_TO_MB(descriptor.SizeInBytes) << " vs "
                        << GPGMM_BYTES_TO_MB(
                               (currentVideoInfo.Budget > currentVideoInfo.CurrentUsage)
                                   ? currentVideoInfo.Budget - currentVideoInfo.CurrentUsage
                                   : 0)
                        << " MBs) and HEAP_FLAG_ALWAYS_IN_BUDGET was specified.";
                }

                return E_OUTOFMEMORY;
            }
        }

        ComPtr<ID3D12Pageable> pageable;
        ReturnIfFailedDevice(createHeapFn(pCreateHeapContext, &pageable),
                             GetDevice(pageable.Get()));

        // Pageable-based type is required for residency-managed heaps.
        ReturnIfNullptr(pageable);

        GPGMM_TRACE_EVENT_OBJECT_CALL("Heap.CreateHeap",
                                      (CREATE_HEAP_DESC{descriptor, pageable.Get()}));

        std::unique_ptr<Heap> heap(new Heap(pageable, descriptor, isResidencyDisabled));

        if (!isResidencyDisabled) {
            // Check if the underlying memory was implicitly made resident.
            D3D12_HEAP_FLAGS resourceHeapFlags = D3D12_HEAP_FLAG_NONE;
            if (SUCCEEDED(GetResourceHeapFlags(pageable, &resourceHeapFlags))) {
                // Resource heaps created without the "create not resident" flag are always
                // resident.
                if (!(resourceHeapFlags & D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT)) {
                    heap->mState = RESIDENCY_STATUS_CURRENT_RESIDENT;
                } else {
                    heap->mState = RESIDENCY_STATUS_PENDING_RESIDENCY;
                }
            }

            // Heap created not resident requires no budget to be created.
            if (heap->mState == RESIDENCY_STATUS_PENDING_RESIDENCY &&
                (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET)) {
                gpgmm::ErrorLog(MessageId::kInvalidArgument)
                    << "Creating a heap always in budget cannot be used with "
                       "D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT.";
                return E_INVALIDARG;
            }

            // Only heap types that are known to be created resident are eligable for evicition and
            // should be always inserted in the residency cache. For other heap types (eg.
            // descriptor heap), they must be manually locked and unlocked to be inserted into the
            // residency cache.
            if (heap->mState != RESIDENCY_STATUS_UNKNOWN) {
                ReturnIfFailed(residencyManager->InsertHeap(heap.get()));
            } else {
                if (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_RESIDENCY) {
                    ReturnIfFailed(residencyManager->LockHeap(heap.get()));
                    ReturnIfFailed(residencyManager->UnlockHeap(heap.get()));
                    ASSERT(heap->mState == RESIDENCY_STATUS_CURRENT_RESIDENT);
                }
            }
        } else {
            if (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_RESIDENCY) {
                gpgmm::WarningLog(MessageId::kInvalidArgument)
                    << "HEAP_FLAG_ALWAYS_IN_RESIDENCY was specified but had no effect becauase "
                       "residency management is "
                       "not being used.";
            }
        }

        ReturnIfFailed(heap->SetDebugName(descriptor.DebugName));
        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(heap.get(), descriptor);

        gpgmm::DebugLog(MessageId::kMemoryAllocated)
            << "Created heap (" << WCharToUTF8(heap->GetDebugName()) << "=" << ToHexStr(heap.get())
            << "), Size=" << heap->GetInfo().SizeInBytes
            << ", ID3D12Pageable=" << ToHexStr(heap->mPageable.Get());

        if (ppHeapOut != nullptr) {
            *ppHeapOut = heap.release();
        }

        return S_OK;
    }

    Heap::Heap(ComPtr<ID3D12Pageable> pageable,
               const HEAP_DESC& descriptor,
               bool isResidencyDisabled)
        : MemoryBase(descriptor.SizeInBytes, descriptor.Alignment),
          mPageable(std::move(pageable)),
          mMemorySegmentGroup(descriptor.MemorySegmentGroup),
          mResidencyLock(0),
          mIsResidencyDisabled(isResidencyDisabled),
          mState(RESIDENCY_STATUS_UNKNOWN) {
        ASSERT(mPageable != nullptr);
        if (!mIsResidencyDisabled) {
            GPGMM_TRACE_EVENT_OBJECT_NEW(this);
        }
    }

    Heap::~Heap() {
        if (mIsResidencyDisabled) {
            return;
        }

        // When a heap is destroyed, it no longer resides in resident memory, so we must evict
        // it from the residency cache. If this heap is not manually removed from the residency
        // cache, the ResidencyManager will attempt to use it after it has been deallocated.
        if (IsInList()) {
            RemoveFromList();
        }

        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
    }

    const char* Heap::GetTypename() const {
        return "Heap";
    }

    uint64_t Heap::GetLastUsedFenceValue() const {
        return mLastUsedFenceValue;
    }

    void Heap::SetLastUsedFenceValue(uint64_t fenceValue) {
        mLastUsedFenceValue = fenceValue;
    }

    DXGI_MEMORY_SEGMENT_GROUP Heap::GetMemorySegmentGroup() const {
        return mMemorySegmentGroup;
    }

    void Heap::AddResidencyLockRef() {
        mResidencyLock.Ref();
    }

    void Heap::ReleaseResidencyLock() {
        mResidencyLock.Unref();
    }

    bool Heap::IsResidencyLocked() const {
        return mResidencyLock.GetRefCount() > 0;
    }

    HEAP_INFO Heap::GetInfo() const {
        return {GetSize(), GetAlignment(), IsResidencyLocked(), IsInList(), mState};
    }

    HRESULT Heap::SetDebugNameImpl(LPCWSTR name) {
        return SetDebugObjectName(mPageable.Get(), name);
    }

    HRESULT STDMETHODCALLTYPE Heap::QueryInterface(REFIID riid, void** ppvObject) {
        return mPageable->QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE Heap::AddRef() {
        return Unknown::AddRef();
    }

    ULONG STDMETHODCALLTYPE Heap::Release() {
        return Unknown::Release();
    }

    void Heap::SetResidencyState(RESIDENCY_STATUS newStatus) {
        mState = newStatus;
    }

    LPCWSTR Heap::GetDebugName() const {
        return DebugObject::GetDebugName();
    }

    HRESULT Heap::SetDebugName(LPCWSTR Name) {
        return DebugObject::SetDebugName(Name);
    }

}  // namespace gpgmm::d3d12
