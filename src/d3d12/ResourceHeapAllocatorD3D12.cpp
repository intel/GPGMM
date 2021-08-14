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

#include "src/d3d12/ResourceHeapAllocatorD3D12.h"
#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResourceAllocatorD3D12.h"

namespace gpgmm { namespace d3d12 {

    ResourceHeapAllocator::ResourceHeapAllocator(ResourceAllocator* resourceAllocator,
                                                 D3D12_HEAP_TYPE heapType,
                                                 D3D12_HEAP_FLAGS heapFlags,
                                                 DXGI_MEMORY_SEGMENT_GROUP memorySegment,
                                                 uint64_t heapSize,
                                                 uint64_t heapAlignment)
        : mResourceAllocator(resourceAllocator),
          mHeapType(heapType),
          mHeapFlags(heapFlags),
          mMemorySegment(memorySegment),
          mHeapSize(heapSize),
          mHeapAlignment(heapAlignment) {
    }

    void ResourceHeapAllocator::AllocateMemory(MemoryAllocation& allocation) {
        Heap* heap = nullptr;
        if (FAILED(mResourceAllocator->CreateResourceHeap(mHeapSize, mHeapType, mHeapFlags,
                                                          mMemorySegment, mHeapAlignment, &heap))) {
            return;
        }

        AllocationInfo info = {};
        info.mMethod = AllocationMethod::kDirect;
        allocation = {mResourceAllocator, info, kInvalidOffset, static_cast<MemoryBase*>(heap)};
    }

    uint64_t ResourceHeapAllocator::GetMemorySize() const {
        return mHeapSize;
    }

    uint64_t ResourceHeapAllocator::GetMemoryAlignment() const {
        return mHeapAlignment;
    }

    void ResourceHeapAllocator::DeallocateMemory(MemoryAllocation& allocation) {
        Heap* resourceHeap = static_cast<Heap*>(allocation.GetMemory());
        mResourceAllocator->FreeResourceHeap(resourceHeap);
    }

    void ResourceHeapAllocator::Release() {
        ASSERT(false);
    }

}}  // namespace gpgmm::d3d12
