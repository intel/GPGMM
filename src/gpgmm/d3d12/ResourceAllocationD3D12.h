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

#include "gpgmm/common/MemoryAllocation.h"
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/NonCopyable.h"
#include "include/gpgmm_export.h"

namespace gpgmm { namespace d3d12 {

    class Heap;
    class ResidencyManager;
    class ResidencySet;

    struct RESOURCE_ALLOCATION_INFO {
        uint64_t SizeInBytes;
        uint64_t HeapOffset;
        uint64_t OffsetFromResource;
        AllocationMethod Method;
        Heap* ResourceHeap;
        ID3D12Resource* Resource;
    };

    class GPGMM_EXPORT ResourceAllocation final : public MemoryAllocation,
                                                  public NonCopyable,
                                                  public IUnknownImpl {
      public:
        // Constructs a resource allocation from memory containing one or more resources.
        ResourceAllocation(ResidencyManager* residencyManager,
                           MemoryAllocator* allocator,
                           uint64_t offsetFromHeap,
                           MemoryBlock* block,
                           AllocationMethod method,
                           UniqueComPtr<ID3D12Resource> placedResource,
                           Heap* resourceHeap);

        // Constructs a resource allocation within a resource.
        ResourceAllocation(ResidencyManager* residencyManager,
                           MemoryAllocator* allocator,
                           MemoryBlock* block,
                           uint64_t offsetFromResource,
                           UniqueComPtr<ID3D12Resource> resource,
                           Heap* resourceHeap);

        ~ResourceAllocation() override;

        // Gets the CPU pointer to the specificed subresource of the resource allocation.
        // If sub-allocated within the resource, the read or write range and
        // pointer value will start from the allocation instead of the resource.
        HRESULT Map(uint32_t subresource = 0,
                    const D3D12_RANGE* readRange = nullptr,
                    void** dataOut = nullptr);

        void Unmap(uint32_t subresource = 0, const D3D12_RANGE* writtenRange = nullptr);

        // Returns the resource owned by this allocation.
        ID3D12Resource* GetResource() const;

        // Tracks the resource allocation memory for residency.
        HRESULT UpdateResidency(ResidencySet* residencySet) const;

        // Returns if the resource allocation memory will be made resident or not.
        bool IsResident() const;

        // Returns the GPU virtual address of the resource allocation.
        // If sub-allocated within the resource, the GPU virtual address will
        // start from the allocation instead of the resource.
        D3D12_GPU_VIRTUAL_ADDRESS GetGPUVirtualAddress() const;

        // Returns the start of the allocation.
        // If sub-allocated within the resource, the offset could be greater than zero.
        uint64_t GetOffsetFromResource() const;

        RESOURCE_ALLOCATION_INFO GetInfo() const;

        const char* GetTypename() const;

        // Returns the heap assigned to this resource allocation.
        Heap* GetMemory() const;

      private:
        void DeleteThis() override;

        ResidencyManager* const mResidencyManager;
        UniqueComPtr<ID3D12Resource> mResource;

        const uint64_t mOffsetFromResource;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
