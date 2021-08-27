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

#ifndef GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
#define GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_

#include "src/MemoryAllocator.h"
#include "src/d3d12/ResourceAllocationD3D12.h"

#include <array>
#include <memory>
#include <cstdint>

struct ID3D12Device;
struct IDXGIAdapter3;

namespace gpgmm {

    class PooledMemoryAllocator;
    class VirtualBuddyAllocator;

    namespace d3d12 {

        class ResidencyManager;
        class ResourceHeapAllocator;

        typedef enum ALLOCATOR_FLAGS {
            ALLOCATOR_ALWAYS_COMMITED = 0x1,
            ALLOCATOR_ALWAYS_IN_BUDGET = 0x2,
        } ALLOCATOR_FLAGS;

        struct ALLOCATOR_DESC {
            Microsoft::WRL::ComPtr<ID3D12Device> Device;
            Microsoft::WRL::ComPtr<IDXGIAdapter3> Adapter;

            ALLOCATOR_FLAGS Flags;
            bool IsUMA;

            // Determines if the resource heap can mix resource categories (both texture and
            // buffers). Use CheckFeatureSupport to get supported tier.
            uint32_t ResourceHeapTier;

            // The minimum size of the created resource heap.
            // If the allocation exceeds |PreferredResourceHeapSize|, it cannot sub-allocate. If the
            // resource heap size is too small, there will be no beneifit to sub-allocate the
            // resource. By default, a preferred heap size of zero means the default heap size of
            // 4MB will be used.
            uint64_t PreferredResourceHeapSize;

            // Any resource greater than |MaxResourceSizeForPooling| will not be pool-allocated.
            // This avoids keeping large resource heaps in memory for infrequently created large
            // resources.
            // By default, a max resource heap size of zero means created resources will always be
            // pool-allocated.
            uint64_t MaxResourceSizeForPooling;

            // The total video memory available to the allocator to budget, expressed as a
            // percentage. For example, 0.95 means 95% of video memory can be budgeted, always
            // leaving 5% for the the OS and other applications.
            float TotalMemorySegmentBudgetLimit;
        };

        typedef enum ALLOCATION_FLAGS {} ALLOCATION_FLAGS;

        struct ALLOCATION_DESC {
            ALLOCATION_FLAGS Flags;
            D3D12_HEAP_TYPE HeapType;
        };

        // Resource heap types + flags combinations are named after the D3D constants.
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_flags
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_type
        enum ResourceHeapKind {

            // Resource heap tier 2
            // Allows resource heaps to contain all buffer and textures types.
            // This enables better heap re-use by avoiding the need for separate heaps and
            // also reduces fragmentation.
            Readback_AllBuffersAndTextures,
            Upload_AllBuffersAndTextures,
            Default_AllBuffersAndTextures,

            // Resource heap tier 1
            // Resource heaps only support types from a single resource category.
            Readback_OnlyBuffers,
            Upload_OnlyBuffers,
            Default_OnlyBuffers,

            Default_OnlyNonRenderableOrDepthTextures,
            Default_OnlyRenderableOrDepthTextures,

            EnumCount,
            InvalidEnum = EnumCount,
        };

        // Manages a list of resource allocators used by the device to create resources using
        // multiple allocation methods.
        class ResourceAllocator : public MemoryAllocator {
          public:
            ResourceAllocator(const ALLOCATOR_DESC& descriptor);
            ~ResourceAllocator() override;

            HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                   const D3D12_RESOURCE_DESC& resourceDescriptor,
                                   D3D12_RESOURCE_STATES initialUsage,
                                   const D3D12_CLEAR_VALUE* pClearValue,
                                   ResourceAllocation** ppResourceAllocation);

            HRESULT CreateResource(ComPtr<ID3D12Resource> resource,
                                   ResourceAllocation** ppResourceAllocation);

            ResidencyManager* GetResidencyManager();

          private:
            friend ResourceHeapAllocator;
            friend ResourceAllocation;

            // MemoryAllocator interface
            void SubAllocateMemory(uint64_t size,
                                   uint64_t alignment,
                                   MemoryAllocation& allocation) override;
            void AllocateMemory(MemoryAllocation& allocation) override;
            void DeallocateMemory(MemoryAllocation& resourceHeap) override;
            void ReleaseMemory() override;

            uint64_t GetMemorySize() const override;
            uint64_t GetMemoryAlignment() const override;

            HRESULT CreatePlacedResource(D3D12_HEAP_TYPE heapType,
                                         const D3D12_RESOURCE_DESC* requestedResourceDescriptor,
                                         const D3D12_CLEAR_VALUE* pClearValue,
                                         D3D12_RESOURCE_STATES initialUsage,
                                         ResourceAllocation** ppResourceAllocation);

            HRESULT CreateCommittedResource(D3D12_HEAP_TYPE heapType,
                                            const D3D12_RESOURCE_DESC* resourceDescriptor,
                                            const D3D12_CLEAR_VALUE* pClearValue,
                                            D3D12_RESOURCE_STATES initialUsage,
                                            ResourceAllocation** ppResourceAllocation);

            HRESULT CreateResourceHeap(uint64_t size,
                                       D3D12_HEAP_TYPE heapType,
                                       D3D12_HEAP_FLAGS heapFlags,
                                       DXGI_MEMORY_SEGMENT_GROUP memorySegment,
                                       uint64_t heapAlignment,
                                       Heap** ppResourceHeap);

            ComPtr<ID3D12Device> mDevice;

            bool mIsUMA;
            uint32_t mResourceHeapTier;
            bool mIsAlwaysCommitted;
            bool mIsAlwaysInBudget;
            uint64_t mMaxResourceSizeForPooling;

            std::array<std::unique_ptr<VirtualBuddyAllocator>, ResourceHeapKind::EnumCount>
                mPlacedAllocators;

            std::array<std::unique_ptr<VirtualBuddyAllocator>, ResourceHeapKind::EnumCount>
                mPooledPlacedAllocators;

            std::array<std::unique_ptr<ResourceHeapAllocator>, ResourceHeapKind::EnumCount>
                mResourceHeapAllocators;

            std::array<std::unique_ptr<PooledMemoryAllocator>, ResourceHeapKind::EnumCount>
                mPooledResourceHeapAllocators;

            std::unique_ptr<ResidencyManager> mResidencyManager;
        };

    }  // namespace d3d12
}  // namespace gpgmm

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
