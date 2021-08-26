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

#include "src/Memory.h"
#include "src/common/LinkedList.h"
#include "src/d3d12/d3d12_platform.h"

#include <memory>

namespace gpgmm { namespace d3d12 {

    class ResidencySet;

    // This class is used to represent ID3D12Heap allocations, as well as an implicit heap
    // representing a directly allocated resource, and also serves as a node within
    // the ResidencyManager's LRU cache. This node is inserted into the LRU-cache when it is first
    // allocated, and any time it is scheduled to be used by the GPU. This node is removed from the
    // LRU cache when it is evicted from resident memory due to budget constraints, or when the
    // pageable allocation is released.
    class Heap : public MemoryBase, public LinkNode<Heap> {
      public:
        Heap(ComPtr<ID3D12Pageable> d3d12Pageable,
             const DXGI_MEMORY_SEGMENT_GROUP& memorySegment,
             uint64_t size);
        ~Heap();

        ID3D12Pageable* GetD3D12Pageable() const;
        ID3D12Heap* GetD3D12Heap() const;

        void UpdateResidency(ResidencySet* residencySet);

        // The residency manager must know the last fence value that any portion of the pageable was
        // submitted to be used so that we can ensure this pageable stays resident in memory at
        // least until that fence has completed.
        uint64_t GetLastUsedFenceValue() const;
        void SetLastUsedFenceValue(uint64_t fenceValue);

        DXGI_MEMORY_SEGMENT_GROUP GetMemorySegment() const;

        uint64_t GetSize() const;

        bool IsInResidencyLRUCache() const;

        // In some scenarios, such as async buffer mapping or descriptor heaps, we must lock
        // residency to ensure the pageable cannot be evicted. Because multiple buffers may be
        // mapped in a single heap, we must track the number of resources currently locked.
        void IncrementResidencyLock();
        void DecrementResidencyLock();
        bool IsResidencyLocked() const;

        bool IsResident() const;

      private:
        ComPtr<ID3D12Pageable> mD3d12Pageable;

        // mLastUsedFenceValue denotes the last time this pageable was submitted to the GPU.
        uint64_t mLastUsedFenceValue = 0;
        DXGI_MEMORY_SEGMENT_GROUP mMemorySegment;
        uint32_t mResidencyLockRefCount = 0;
        uint64_t mSize = 0;
    };
}}  // namespace gpgmm::d3d12

#endif
