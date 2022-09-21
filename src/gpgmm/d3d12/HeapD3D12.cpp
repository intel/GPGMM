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

#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm::d3d12 {

    // static
    HRESULT Heap::CreateHeap(const HEAP_DESC& descriptor,
                             ResidencyManager* const pResidencyManager,
                             CreateHeapFn&& createHeapFn,
                             Heap** ppHeapOut) {
        const bool isResidencyDisabled = (pResidencyManager == nullptr);

        // Ensure enough budget exists before allocating to avoid an out-of-memory error.
        if (!isResidencyDisabled && (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET)) {
            ReturnIfFailed(pResidencyManager->EnsureInBudget(descriptor.SizeInBytes,
                                                             descriptor.MemorySegmentGroup));
        }

        ComPtr<ID3D12Pageable> pageable;
        ReturnIfFailed(createHeapFn(&pageable));

        // Pageable-based type is required for residency-managed heaps.
        if (pageable == nullptr) {
            gpgmm::ErrorLog() << "Unable to create heap because memory does not exist.";
            return E_POINTER;
        }

        GPGMM_TRACE_EVENT_OBJECT_CALL("Heap.CreateHeap",
                                      (CREATE_HEAP_DESC{descriptor, pageable.Get()}));

        std::unique_ptr<Heap> heap(new Heap(pageable, descriptor, isResidencyDisabled));

        if (!isResidencyDisabled) {
            ReturnIfFailed(pResidencyManager->InsertHeap(heap.get()));

            // Check if the underlying memory was implicitly made resident.
            // This is always the case for resource heaps unless the "not resident" flag was
            // explicitly used in createHeapFn().
            D3D12_HEAP_FLAGS resourceHeapFlags = D3D12_HEAP_FLAG_NONE;

            ComPtr<ID3D12Heap> d3d12Heap;
            if (SUCCEEDED(pageable.As(&d3d12Heap))) {
                resourceHeapFlags = d3d12Heap->GetDesc().Flags;
            }

            ComPtr<ID3D12Resource> committedResource;
            if (SUCCEEDED(pageable.As(&committedResource))) {
                ReturnIfFailed(committedResource->GetHeapProperties(nullptr, &resourceHeapFlags));
            }

            if ((d3d12Heap || committedResource) &&
                !(resourceHeapFlags & D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT)) {
                heap->mState = CURRENT_RESIDENT;
            } else {
                heap->mState = PENDING_RESIDENCY;
            }
        }

        ReturnIfFailed(heap->SetDebugName(descriptor.DebugName));
        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(heap.get(), descriptor);

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
          mState(RESIDENCY_UNKNOWN) {
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
        return {IsResidencyLocked(), mState};
    }

    HRESULT Heap::SetDebugNameImpl(const std::string& name) {
        return SetDebugObjectName(mPageable.Get(), name);
    }

    HRESULT STDMETHODCALLTYPE Heap::QueryInterface(REFIID riid, void** ppvObject) {
        return mPageable->QueryInterface(riid, ppvObject);
    }

    void Heap::SetResidencyState(RESIDENCY_STATUS newStatus) {
        mState = newStatus;
    }

    bool Heap::IsInResidencyLRUCacheForTesting() const {
        return IsInList();
    }

    bool Heap::IsResidencyLockedForTesting() const {
        return IsResidencyLocked();
    }

}  // namespace gpgmm::d3d12
