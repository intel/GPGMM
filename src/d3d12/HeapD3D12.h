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

#ifndef GPGMM_D3D12_HEAPD3D12_H_
#define GPGMM_D3D12_HEAPD3D12_H_

#include "../common/LinkedList.h"
#include "../common/RefCount.h"
#include "src/Memory.h"
#include "src/d3d12/d3d12_platform.h"

#include <memory>

namespace gpgmm { namespace d3d12 {

    class ResidencySet;
    class ResidencyManager;
    class ResourceAllocator;

    struct HEAP_DESC {
        size_t Size;
        bool IsResident;
        DXGI_MEMORY_SEGMENT_GROUP MemorySegmentGroup;
    };

    // This class is used to represent ID3D12Heap allocations, as well as an implicit heap
    // representing a directly allocated resource, and also serves as a node within
    // the ResidencyManager's LRU cache. This node is inserted into the LRU-cache when it is first
    // allocated, and any time it is scheduled to be used by the GPU. This node is removed from the
    // LRU cache when it is evicted from resident memory due to budget constraints, or when the
    // pageable allocation is released.
    class Heap : public MemoryBase, public LinkNode<Heap> {
      public:
        Heap(ComPtr<ID3D12Pageable> pageable,
             const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
             uint64_t size);
        ~Heap();

        ID3D12Heap* GetHeap() const;

        HRESULT UpdateResidency(ResidencySet* residencySet);

        bool IsResident() const;

        // Testing only.
        bool IsInResidencyLRUCache() const;
        bool IsResidencyLocked() const;

        HEAP_DESC GetDesc() const;

      private:
        friend ResidencyManager;
        friend ResourceAllocator;

        ComPtr<ID3D12Pageable> GetPageable() const;
        DXGI_MEMORY_SEGMENT_GROUP GetMemorySegmentGroup() const;

        // The residency manager must know the last fence value that any portion of the pageable was
        // submitted to be used so that we can ensure this pageable stays resident in memory at
        // least until that fence has completed.
        uint64_t GetLastUsedFenceValue() const;
        void SetLastUsedFenceValue(uint64_t fenceValue);

        // Locks residency to ensure the heap cannot be evicted (ex. shader-visible descriptor
        // heaps or mapping resources).
        void AddResidencyLockRef();
        void ReleaseResidencyLock();

        ComPtr<ID3D12Pageable> mPageable;

        // mLastUsedFenceValue denotes the last time this pageable was submitted to the GPU.
        uint64_t mLastUsedFenceValue = 0;
        DXGI_MEMORY_SEGMENT_GROUP mMemorySegmentGroup;
        RefCounted mResidencyLock;
    };
}}  // namespace gpgmm::d3d12

#endif
