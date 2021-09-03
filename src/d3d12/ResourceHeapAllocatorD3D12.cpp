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
#include "src/common/IntegerTypes.h"
#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResourceAllocatorD3D12.h"

namespace gpgmm { namespace d3d12 {

    namespace {
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_flags
        uint64_t GetHeapAlignment(D3D12_HEAP_FLAGS heapFlags) {
            const bool noTexturesAllowedFlags =
                D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES | D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES;
            if ((heapFlags & noTexturesAllowedFlags) == noTexturesAllowedFlags) {
                return D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT;
            }
            // It is preferred to use a size that is a multiple of the alignment.
            // However, MSAA heaps are always aligned to 4MB instead of 64KB. This means
            // if the heap size is too small, the VMM would fragment.
            // TODO: Consider having MSAA vs non-MSAA heaps.
            return D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT;
        }
    }  // namespace

    ResourceHeapAllocator::ResourceHeapAllocator(ResourceAllocator* resourceAllocator,
                                                 D3D12_HEAP_TYPE heapType,
                                                 D3D12_HEAP_FLAGS heapFlags,
                                                 DXGI_MEMORY_SEGMENT_GROUP memorySegment,
                                                 uint64_t heapSize)
        : mResourceAllocator(resourceAllocator),
          mHeapType(heapType),
          mHeapFlags(heapFlags),
          mMemorySegment(memorySegment),
          mHeapSize(heapSize),
          mHeapAlignment(GetHeapAlignment(heapFlags)) {
    }

    void ResourceHeapAllocator::SubAllocateMemory(uint64_t size,
                                                  uint64_t alignment,
                                                  MemoryAllocation& allocation) {
        ASSERT(false);
    }

    void ResourceHeapAllocator::AllocateMemory(MemoryAllocation** ppAllocation) {
        Heap* heap = nullptr;
        if (FAILED(mResourceAllocator->CreateResourceHeap(mHeapSize, mHeapType, mHeapFlags,
                                                          mMemorySegment, mHeapAlignment, &heap))) {
            return;
        }

        AllocationInfo info = {};
        info.mMethod = AllocationMethod::kStandalone;
        *ppAllocation =
            new MemoryAllocation{this, info, kInvalidOffset, static_cast<MemoryBase*>(heap)};
    }

    uint64_t ResourceHeapAllocator::GetMemorySize() const {
        return mHeapSize;
    }

    uint64_t ResourceHeapAllocator::GetMemoryAlignment() const {
        return mHeapAlignment;
    }

    void ResourceHeapAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        mResourceAllocator->DeallocateMemory(allocation);
    }

    void ResourceHeapAllocator::ReleaseMemory() {
        // Nothing to release since this allocator always returns new resource heaps.
    }

}}  // namespace gpgmm::d3d12
