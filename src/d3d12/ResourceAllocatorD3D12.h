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

#include "src/Allocator.h"
#include "src/d3d12/ResourceAllocationD3D12.h"

#include <array>
#include <cstdint>
#include <memory>

struct ID3D12Device;
struct IDXGIAdapter3;

namespace gpgmm {

    class ScopedAllocatorStack;

    namespace d3d12 {

        class ResidencyManager;
        class ResourceHeapAllocator;

        typedef enum ALLOCATOR_FLAGS {

            // Disables all flags. Enabled by default.
            ALLOCATOR_FLAG_NONE = 0x0,

            // Forces standalone committed resource creation. Mostly used to debug problems with
            // placed
            // resource based suballocation.
            ALLOCATOR_ALWAYS_COMMITED = 0x1,

            // Ensures resources are always within the resource budget at creation time. Mostly used
            // to debug
            // with residency being over committed.
            ALLOCATOR_ALWAYS_IN_BUDGET = 0x2,

        } ALLOCATOR_FLAGS;

        struct ALLOCATOR_DESC {
            // Device and adapter used by this allocator. The adapter must support DXGI 1.4
            // to use residency. Required parameters.
            Microsoft::WRL::ComPtr<ID3D12Device> Device;
            Microsoft::WRL::ComPtr<IDXGIAdapter> Adapter;

            ALLOCATOR_FLAGS Flags = ALLOCATOR_FLAG_NONE;

            // Determines if this allocator should use shared memory. Use CheckFeatureSupport
            // to check for support. Required parameter.
            bool IsUMA;

            // Determines if the resource heap can mix resource categories (both texture and
            // buffers). Use CheckFeatureSupport to get supported tier. Required parameter.
            uint32_t ResourceHeapTier;

            // Minimum size of the resource heap.
            // If the resource size exceeds |PreferredResourceHeapSize|, it will not sub-allocate a
            // resource within a heap. By default, a preferred heap size of zero means the default
            // heap size of 4MB will always be used.
            uint64_t PreferredResourceHeapSize;

            // Maximum size of the resource heap.
            // If the resource size exceeds |MaxResourceHeapSize|, CreateResource will always return
            // E_OUTOFMEMORY. By default, a max resource heap size of zero means the max heap
            // size of 32GB is allowed.
            uint64_t MaxResourceHeapSize;

            // Maximum resource size allowed to be pool-allocated.
            // If the resource size is greater than |MaxResourceSizeForPooling|, it will not be
            // pool-allocated. By default, a max resource heap size of zero means created resources
            // will always be pool-allocated reguardless of size.
            uint64_t MaxResourceSizeForPooling;

            // Maximum video memory available to budget by the allocator, expressed as a
            // percentage. By default, the max video memory available is 0.95 or 95% of video memory
            // can be budgeted, always leaving 5% for the OS and other applications.
            float MaxVideoMemoryBudget;

            // Total memory available to budget for resources created by this allocator.
            // By default, a total resource budget limit of zero means there is no budget set.
            uint64_t TotalResourceBudgetLimit;
        };

        typedef enum ALLOCATION_FLAGS {

            // Disables all flags. Enabled by default.
            ALLOCATION_FLAG_NONE = 0x0,

        } ALLOCATION_FLAGS;

        struct ALLOCATION_DESC {
            ALLOCATION_FLAGS Flags = ALLOCATION_FLAG_NONE;
            D3D12_HEAP_TYPE HeapType = D3D12_HEAP_TYPE_DEFAULT;
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
        class ResourceAllocator : public AllocatorBase {
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

            HRESULT CreatePlacedResource(const MemoryAllocation& subAllocation,
                                         const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo,
                                         const D3D12_RESOURCE_DESC* resourceDescriptor,
                                         const D3D12_CLEAR_VALUE* pClearValue,
                                         D3D12_RESOURCE_STATES initialUsage,
                                         ResourceAllocation** ppResourceAllocation);

            HRESULT CreateCommittedResource(D3D12_HEAP_TYPE heapType,
                                            D3D12_HEAP_FLAGS heapFlags,
                                            const D3D12_RESOURCE_ALLOCATION_INFO& resourceInfo,
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

            void FreeResourceHeap(Heap* resourceHeap);

            ComPtr<ID3D12Device> mDevice;

            bool mIsUMA;
            uint32_t mResourceHeapTier;
            bool mIsAlwaysCommitted;
            bool mIsAlwaysInBudget;
            uint64_t mMaxResourceSizeForPooling;
            uint64_t mMaxResourceHeapSize;

            std::array<std::unique_ptr<ScopedAllocatorStack>, ResourceHeapKind::EnumCount>
                mAllocators;

            std::unique_ptr<ResidencyManager> mResidencyManager;
        };

    }  // namespace d3d12
}  // namespace gpgmm

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
