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

#include "gpgmm/TraceEvent.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencySetD3D12.h"

namespace gpgmm { namespace d3d12 {
    Heap::Heap(ComPtr<ID3D12Pageable> pageable,
               const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
               uint64_t size)
        : MemoryBase(size),
          mPageable(std::move(pageable)),
          mMemorySegmentGroup(memorySegmentGroup),
          mResidencyLock(0) {
        ASSERT(mPageable != nullptr);

        TRACE_EVENT_OBJECT_CREATED_WITH_ID("GPUMemoryBlock", this);
        d3d12::LogObject("GPUMemoryBlock", this, GetDesc());

        mPageable->SetName(L"GPGMM managed heap");
    }

    // When a pageable is destroyed, it no longer resides in resident memory, so we must evict
    // it from the LRU cache. If this heap is not manually removed from the LRU-cache, the
    // ResidencyManager will attempt to use it after it has been deallocated.
    Heap::~Heap() {
        if (IsInResidencyLRUCache()) {
            RemoveFromList();
        }

        TRACE_EVENT_OBJECT_DELETED_WITH_ID("GPUMemoryBlock", this);
    }

    ComPtr<ID3D12Pageable> Heap::GetPageable() const {
        return mPageable;
    }

    ID3D12Heap* Heap::GetHeap() const {
        ComPtr<ID3D12Heap> heap;
        mPageable.As(&heap);
        return heap.Get();
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
        return mResidencyLock.RefCount() > 0;
    }

    bool Heap::IsResident() const {
        return IsInList() || IsResidencyLocked();
    }

    HRESULT Heap::UpdateResidency(ResidencySet* residencySet) {
        return residencySet->Insert(this);
    }

    HEAP_DESC Heap::GetDesc() const {
        return {GetSize(), IsResident(), mMemorySegmentGroup, RefCount(), GetPool()};
    }
}}  // namespace gpgmm::d3d12
