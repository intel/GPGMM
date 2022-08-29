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
#include "gpgmm/d3d12/DebugObjectD3D12.h"
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "gpgmm/d3d12/d3d12_platform.h"
#include "gpgmm/utils/NonCopyable.h"
#include "include/gpgmm_export.h"

namespace gpgmm::d3d12 {

    class DebugResourceAllocator;
    class Heap;
    class ResidencyManager;
    class ResidencyList;
    class ResourceAllocator;

    /** \struct RESOURCE_ALLOCATION_DESC
    Describes a resource allocation.
    */
    struct RESOURCE_ALLOCATION_DESC {
        /** \brief Requested size, in bytes, of the resource allocation.

        Must be non-zero.
        */
        uint64_t RequestSizeInBytes;

        /** \brief Offset, in bytes, of the resource in the heap.
         */
        uint64_t HeapOffset;

        /** \brief Offset, in bytes, of the allocation, from the start of the
        resource.

         Always zero when the resource is placed in a heap or created with it's own heap.
        */
        uint64_t OffsetFromResource;

        /** \brief Method to describe how the allocation was created.

        The Method determines how to figure out the size of the allocation.
        */
        AllocationMethod Method;

        /** \brief Debug name associated with the resource allocation.
         */
        std::string DebugName;
    };

    /** \struct RESOURCE_ALLOCATION_INFO
    Additional information about the resource allocation.
    */
    struct RESOURCE_ALLOCATION_INFO {
        /** \brief Created size, in bytes, of the resource allocation.

        Must be non-zero. SizeInBytes is always a multiple of the alignment.
        */
        uint64_t SizeInBytes;

        /** \brief Created alignment, in bytes, of the resource allocation.

        Must be non-zero.
        */
        uint64_t Alignment;
    };

    /** \brief ResourceAllocation is MemoryAllocation that contains a ID3D12Resource.

    It can represent a allocation using a resource in one of three ways: 1) ID3D12Resource "placed"
    in a ID3D12Heap, 2) a ID3D12Resource at a specific offset, or 3) a ID3D12Resource without a
    ID3D12Heap (called a committed resource).

    It is recommend to use ResourceAllocation instead of ID3D12Resource (1:1) for perfoming D3D12
    operations with it (eg. Map, Unmap, etc).
    */
    class GPGMM_EXPORT ResourceAllocation final : public MemoryAllocation,
                                                  public NonCopyable,
                                                  public DebugObject,
                                                  public IUnknownImpl {
      public:
        ~ResourceAllocation() override;

        /** \brief Maps the resource allocation.

        Gets the CPU pointer to the specificed subresource of the resource allocation.

        If sub-allocated within the resource, the read or write range and
        pointer value will start from the allocation instead of the resource.

        @param subresource Specifies the index number of the subresource.
        @param readRange A pointer to a D3D12_RANGE structure that describes the range of memory to
        access.
        @param[out] dataOut A pointer to a memory block that receives a pointer to the resource
        data.
        */
        HRESULT Map(uint32_t subresource = 0,
                    const D3D12_RANGE* readRange = nullptr,
                    void** dataOut = nullptr);

        /** \brief Unmaps the resource allocation.

        Invalidates the CPU pointer to the specified subresource in the resource.

        @param subresource Specifies the index number of the subresource.
        @param writtenRange A pointer to a D3D12_RANGE structure that describes the range of memory
        to unmap.
        */
        void Unmap(uint32_t subresource = 0, const D3D12_RANGE* writtenRange = nullptr);

        /** \brief Returns the resource owned by this allocation.

        \return Pointer to ID3D12Resource, owned by this allocation.
        */
        ID3D12Resource* GetResource() const;

        /** \brief Check if the resource allocation was made resident or not.

        \return True if resident, else, false.
        */
        bool IsResident() const;

        /** \brief Returns the GPU virtual address of the resource allocation.

        If sub-allocated within the resource, the GPU virtual address will
        start from the allocation instead of the resource.

        \return A D3D12_GPU_VIRTUAL_ADDRESS, equal to UINT64, to represent a location in GPU memory.
        */
        D3D12_GPU_VIRTUAL_ADDRESS GetGPUVirtualAddress() const;

        /** \brief Returns the start of the allocation in the resource.

        If sub-allocated within the resource, the offset could be greater than zero.

        \return A offset, in bytes, of the start of this allocation in the resource.
        */
        uint64_t GetOffsetFromResource() const;

        /** \brief Returns information about this resource allocation.

        \return A RESOURCE_ALLOCATION_INFO struct containing the information.
        */
        RESOURCE_ALLOCATION_INFO GetInfo() const;

        /** \brief Returns the class name of this allocation.

        \return A pointer to a C character string with data, "ResourceAllocation".
        */
        const char* GetTypename() const;

        /** \brief Returns the heap assigned to this resource allocation.

        \return A pointer to the Heap used by this resource allocation.
        */
        Heap* GetMemory() const;

      private:
        friend ResourceAllocator;

        ResourceAllocation(const RESOURCE_ALLOCATION_DESC& desc,
                           ResidencyManager* residencyManager,
                           MemoryAllocator* allocator,
                           Heap* resourceHeap,
                           MemoryBlock* block,
                           ComPtr<ID3D12Resource> resource);

        // Only DebugResourceAllocator may inject itself to ensure |this| cannot leak.
        friend DebugResourceAllocator;
        void SetDebugAllocator(MemoryAllocator* allocator);

        HRESULT SetDebugNameImpl(const std::string& name) override;

        void DeleteThis() override;

        ResidencyManager* const mResidencyManager;
        ComPtr<ID3D12Resource> mResource;

        const uint64_t mOffsetFromResource;
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
