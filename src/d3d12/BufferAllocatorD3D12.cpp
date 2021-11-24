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

#include "src/d3d12/BufferAllocatorD3D12.h"
#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResourceAllocationD3D12.h"
#include "src/d3d12/ResourceAllocatorD3D12.h"

namespace gpgmm { namespace d3d12 {

    BufferAllocator::BufferAllocator(ResourceAllocator* resourceAllocator,
                                     D3D12_HEAP_TYPE heapType,
                                     D3D12_RESOURCE_FLAGS resourceFlags,
                                     D3D12_RESOURCE_STATES initialResourceState,
                                     uint64_t resourceSize,
                                     uint64_t resourceAlignment)
        : mResourceAllocator(resourceAllocator),
          mHeapType(heapType),
          mResourceFlags(resourceFlags),
          mInitialResourceState(initialResourceState),
          mResourceSize(resourceSize),
          mResourceAlignment(resourceAlignment) {
    }

    std::unique_ptr<MemoryAllocation> BufferAllocator::AllocateMemory(uint64_t size,
                                                                      uint64_t alignment,
                                                                      bool neverAllocate) {
        if (GetMemorySize() != size || GetMemoryAlignment() != alignment || neverAllocate) {
            return {};
        }

        D3D12_RESOURCE_DESC resourceDescriptor;
        resourceDescriptor.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        resourceDescriptor.Alignment = alignment;
        resourceDescriptor.Width = size;
        resourceDescriptor.Height = 1;
        resourceDescriptor.DepthOrArraySize = 1;
        resourceDescriptor.MipLevels = 1;
        resourceDescriptor.Format = DXGI_FORMAT_UNKNOWN;
        resourceDescriptor.SampleDesc.Count = 1;
        resourceDescriptor.SampleDesc.Quality = 0;
        resourceDescriptor.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        resourceDescriptor.Flags = mResourceFlags;

        // Optimized clear is not supported for buffers.
        Heap* resourceHeap = nullptr;
        if (FAILED(mResourceAllocator->CreateCommittedResource(
                mHeapType, D3D12_HEAP_FLAG_NONE, size, &resourceDescriptor,
                /*pOptimizedClearValue*/ nullptr, mInitialResourceState, nullptr, &resourceHeap))) {
            return nullptr;
        }

        return std::make_unique<MemoryAllocation>(/*allocator*/ this, resourceHeap);
    }

    void BufferAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        ASSERT(allocation != nullptr);
        Heap* heap = static_cast<Heap*>(allocation->GetMemory());
        mResourceAllocator->FreeResourceHeap(heap);
    }

    uint64_t BufferAllocator::GetMemorySize() const {
        return mResourceSize;
    }

    uint64_t BufferAllocator::GetMemoryAlignment() const {
        return mResourceAlignment;
    }

}}  // namespace gpgmm::d3d12
