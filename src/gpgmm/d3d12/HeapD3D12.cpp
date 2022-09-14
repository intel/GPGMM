// Copyright 2020 The Dawn Authors
// Copyright 2021 The GPGMM Authors
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
        // Ensure enough free memory exists before allocating to avoid an out-of-memory error
        // when over budget.
        if (pResidencyManager != nullptr && (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET)) {
            ReturnIfFailed(pResidencyManager->EnsureInBudget(descriptor.SizeInBytes,
                                                             descriptor.MemorySegmentGroup));
        }

        ComPtr<ID3D12Pageable> pageable;
        ReturnIfFailed(createHeapFn(&pageable));

        GPGMM_TRACE_EVENT_OBJECT_CALL("Heap.CreateHeap",
                                      (CREATE_HEAP_DESC{descriptor, pageable.Get()}));

        std::unique_ptr<Heap> heap(new Heap(std::move(pageable), descriptor));

        if (pResidencyManager != nullptr) {
            ReturnIfFailed(pResidencyManager->InsertHeap(heap.get()));
        }

        ReturnIfFailed(heap->SetDebugName(descriptor.DebugName));
        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(heap.get(), descriptor);

        if (ppHeapOut != nullptr) {
            *ppHeapOut = heap.release();
        }

        return S_OK;
    }

    Heap::Heap(ComPtr<ID3D12Pageable> pageable, const HEAP_DESC& descriptor)
        : MemoryBase(descriptor.SizeInBytes, descriptor.Alignment),
          mPageable(std::move(pageable)),
          mMemorySegmentGroup(descriptor.MemorySegmentGroup),
          mResidencyLock(0),
          mIsExternal(descriptor.Flags & HEAP_FLAG_NEVER_USE_RESIDENCY) {
        ASSERT(mPageable != nullptr);
        if (!mIsExternal) {
            GPGMM_TRACE_EVENT_OBJECT_NEW(this);
        }
    }

    // When a pageable is destroyed, it no longer resides in resident memory, so we must evict
    // it from the LRU cache. If this heap is not manually removed from the LRU-cache, the
    // ResidencyManager will attempt to use it after it has been deallocated.
    Heap::~Heap() {
        // Externally created heaps do not support residency.
        if (mIsExternal) {
            return;
        }

        if (IsInResidencyLRUCache()) {
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

    bool Heap::IsInResidencyLRUCache() const {
        return IsInList();
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

    bool Heap::IsResident() const {
        return IsInList() || IsResidencyLocked();
    }

    HEAP_INFO Heap::GetInfo() const {
        return {IsResident()};
    }

    HRESULT Heap::SetDebugNameImpl(const std::string& name) {
        return SetDebugObjectName(mPageable.Get(), name);
    }

    HRESULT STDMETHODCALLTYPE Heap::QueryInterface(REFIID riid, void** ppvObject) {
        return mPageable->QueryInterface(riid, ppvObject);
    }
}  // namespace gpgmm::d3d12
