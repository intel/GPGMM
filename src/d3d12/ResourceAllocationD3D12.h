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

#ifndef GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
#define GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_

#include "../common/NonCopyable.h"
#include "src/MemoryAllocation.h"
#include "src/d3d12/IUnknownImplD3D12.h"
#include "src/d3d12/d3d12_platform.h"

namespace gpgmm { namespace d3d12 {

    class Heap;
    class ResourceAllocator;
    class ResidencyManager;
    class ResidencySet;

    struct RESOURCE_ALLOCATION_DESC {
        uint64_t Size;
        uint64_t HeapOffset;
        uint64_t OffsetFromResource;
        AllocationMethod Method;
        Heap* ResourceHeap;
    };

    class ResourceAllocation final : public MemoryAllocation,
                                     public NonCopyable,
                                     public IUnknownImpl {
      public:
        // Constructs a sub-allocated resource allocation.
        ResourceAllocation(ResidencyManager* residencyManager,
                           MemoryAllocator* memoryAllocator,
                           uint64_t offsetFromHeap,
                           Block* block,
                           ComPtr<ID3D12Resource> placedResource,
                           Heap* resourceHeap);

        // Constructs a standalone resource allocation using a memory allocator.
        ResourceAllocation(ResidencyManager* residencyManager,
                           MemoryAllocator* memoryAllocator,
                           ComPtr<ID3D12Resource> placedResource,
                           Heap* resourceHeap);

        // Constructs a standalone resource allocation.
        ResourceAllocation(ResidencyManager* residencyManager,
                           ResourceAllocator* resourceAllocator,
                           ComPtr<ID3D12Resource> resource,
                           Heap* resourceHeap);

        // Constructs a sub-allocated allocation within a resource.
        ResourceAllocation(ResidencyManager* residencyManager,
                           MemoryAllocator* memoryAllocator,
                           Block* block,
                           uint64_t offsetFromResource,
                           ComPtr<ID3D12Resource> resource,
                           Heap* resourceHeap);

        // Gets the CPU pointer to the specificed subresource of the resource allocation.
        // If sub-allocated within the resource, the read or write range and
        // pointer value will start from the allocation instead of the resource.
        HRESULT Map(uint32_t subresource = 0,
                    const D3D12_RANGE* readRange = nullptr,
                    void** dataOut = nullptr);

        void Unmap(uint32_t subresource = 0, const D3D12_RANGE* writtenRange = nullptr);

        // Returns the resource owned by this allocation.
        ID3D12Resource* GetResource() const;

        // Tracks the underlying resource heap for residency.
        HRESULT UpdateResidency(ResidencySet* residencySet);

        // Returns the GPU virtual address of the resource allocation.
        // If sub-allocated within the resource, the GPU virtual address will
        // start from the allocation instead of the resource.
        D3D12_GPU_VIRTUAL_ADDRESS GetGPUVirtualAddress() const;

        // Returns the start of the allocation.
        // If sub-allocated within the resource, the offset could be greater than zero.
        uint64_t GetOffsetFromResource() const;

        RESOURCE_ALLOCATION_DESC GetDesc() const;

      private:
        ~ResourceAllocation() override;
        void DeleteThis() override;

        ResourceAllocator* const mResourceAllocator;
        ResidencyManager* const mResidencyManager;
        ComPtr<ID3D12Resource> mResource;

        const uint64_t mOffsetFromResource;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
