// Copyright 2019 The Dawn Authors
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

#ifndef GPGMM_D3D12_RESOURCEHEAPALLOCATORD3D12_H_
#define GPGMM_D3D12_RESOURCEHEAPALLOCATORD3D12_H_

#include "src/MemoryAllocator.h"

#include "src/d3d12/d3d12_platform.h"

namespace gpgmm { namespace d3d12 {

    class ResourceAllocator;

    // Wrapper to allocate a D3D12 heap.
    class ResourceHeapAllocator : public MemoryAllocator {
      public:
        ResourceHeapAllocator(ResourceAllocator* resourceAllocator,
                              D3D12_HEAP_TYPE heapType,
                              D3D12_HEAP_FLAGS heapFlags,
                              DXGI_MEMORY_SEGMENT_GROUP memorySegment,
                              uint64_t heapSize,
                              uint64_t heapAlignment);
        ~ResourceHeapAllocator() override = default;

        // MemoryAllocator interface
        void AllocateMemory(MemoryAllocation& allocation) override;
        void DeallocateMemory(MemoryAllocation& allocation) override;
        void Release() override;

        uint64_t GetMemorySize() const override;
        uint64_t GetMemoryAlignment() const override;

      private:
        ResourceAllocator* mResourceAllocator;
        D3D12_HEAP_TYPE mHeapType;
        D3D12_HEAP_FLAGS mHeapFlags;
        DXGI_MEMORY_SEGMENT_GROUP mMemorySegment;
        uint64_t mHeapSize;
        uint64_t mHeapAlignment;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEHEAPALLOCATORD3D12_H_
