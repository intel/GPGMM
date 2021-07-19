// Copyright 2019 The Dawn Authors
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

#ifndef GPGMM_D3D12_HEAPALLOCATORD3D12_H_
#define GPGMM_D3D12_HEAPALLOCATORD3D12_H_

#include "src/ResourceMemoryAllocator.h"

#include "src/d3d12/d3d12_platform.h"

namespace gpgmm { namespace d3d12 {

    class ResourceAllocator;

    // Wrapper to allocate a D3D12 heap.
    class HeapAllocator : public ResourceMemoryAllocator {
      public:
        HeapAllocator(ComPtr<ID3D12Device> device,
                      ResourceAllocator* resourceAllocator,
                      D3D12_HEAP_TYPE heapType,
                      D3D12_HEAP_FLAGS heapFlags,
                      DXGI_MEMORY_SEGMENT_GROUP memorySegment,
                      uint64_t heapAlignment);
        ~HeapAllocator() override = default;

        ResourceMemoryAllocation Allocate(uint64_t size) override;
        void Deallocate(ResourceMemoryAllocation& allocation) override;
        void Release() override;

      private:
        ComPtr<ID3D12Device> mDevice;
        ResourceAllocator* mResourceAllocator;
        D3D12_HEAP_TYPE mHeapType;
        D3D12_HEAP_FLAGS mHeapFlags;
        DXGI_MEMORY_SEGMENT_GROUP mMemorySegment;
        uint64_t mHeapAlignment;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_HEAPALLOCATORD3D12_H_
