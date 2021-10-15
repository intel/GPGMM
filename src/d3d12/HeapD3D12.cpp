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

#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResidencySetD3D12.h"

namespace gpgmm { namespace d3d12 {
    Heap::Heap(ComPtr<ID3D12Pageable> d3d12Pageable,
               const DXGI_MEMORY_SEGMENT_GROUP& memorySegment,
               uint64_t size)
        : mD3d12Pageable(std::move(d3d12Pageable)), mMemorySegment(memorySegment), mSize(size) {
    }

    // When a pageable is destroyed, it no longer resides in resident memory, so we must evict
    // it from the LRU cache. If this heap is not manually removed from the LRU-cache, the
    // ResidencyManager will attempt to use it after it has been deallocated.
    Heap::~Heap() {
        if (IsInResidencyLRUCache()) {
            RemoveFromList();
        }
    }

    ID3D12Pageable* Heap::GetD3D12Pageable() const {
        return mD3d12Pageable.Get();
    }

    ID3D12Heap* Heap::GetHeap() const {
        ComPtr<ID3D12Heap> heap;
        mD3d12Pageable.As(&heap);
        return heap.Get();
    }

    uint64_t Heap::GetLastUsedFenceValue() const {
        return mLastUsedFenceValue;
    }

    void Heap::SetLastUsedFenceValue(uint64_t fenceValue) {
        mLastUsedFenceValue = fenceValue;
    }

    DXGI_MEMORY_SEGMENT_GROUP Heap::GetMemorySegment() const {
        return mMemorySegment;
    }

    uint64_t Heap::GetSize() const {
        return mSize;
    }

    bool Heap::IsInResidencyLRUCache() const {
        return IsInList();
    }

    void Heap::IncrementResidencyLock() {
        mResidencyLockRefCount++;
    }

    void Heap::DecrementResidencyLock() {
        mResidencyLockRefCount--;
    }

    bool Heap::IsResidencyLocked() const {
        return mResidencyLockRefCount != 0;
    }

    bool Heap::IsResident() const {
        return IsInList() || IsResidencyLocked();
    }

    HRESULT Heap::UpdateResidency(ResidencySet* residencySet) {
        return residencySet->Insert(this);
    }
}}  // namespace gpgmm::d3d12
