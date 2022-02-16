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

#include "gpgmm/d3d12/ResourceHeapAllocatorD3D12.h"

#include "gpgmm/common/Limits.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"

namespace gpgmm { namespace d3d12 {

    ResourceHeapAllocator::ResourceHeapAllocator(ResourceAllocator* resourceAllocator,
                                                 D3D12_HEAP_TYPE heapType,
                                                 D3D12_HEAP_FLAGS heapFlags)
        : mResourceAllocator(resourceAllocator), mHeapType(heapType), mHeapFlags(heapFlags) {
    }

    std::unique_ptr<MemoryAllocation> ResourceHeapAllocator::TryAllocateMemory(
        uint64_t allocationSize,
        uint64_t alignment,
        bool neverAllocate,
        bool cacheSize) {
        if (neverAllocate) {
            return {};
        }

        Heap* resourceHeap = nullptr;
        if (FAILED(mResourceAllocator->CreateResourceHeap(allocationSize, mHeapType, mHeapFlags,
                                                          alignment, &resourceHeap))) {
            return nullptr;
        }

        mInfo.UsedMemoryCount++;
        mInfo.UsedMemoryUsage += allocationSize;

        return std::make_unique<MemoryAllocation>(/*allocator*/ this, resourceHeap);
    }

    void ResourceHeapAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        ASSERT(allocation != nullptr);
        Heap* heap = ToBackend(allocation->GetMemory());

        mInfo.UsedMemoryCount--;
        mInfo.UsedMemoryUsage -= heap->GetSize();

        mResourceAllocator->FreeResourceHeap(heap);
    }

}}  // namespace gpgmm::d3d12
