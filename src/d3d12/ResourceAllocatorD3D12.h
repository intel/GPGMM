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
#include "src/d3d12/IUnknownImplD3D12.h"

#include <array>
#include <memory>

namespace gpgmm {
    class MemoryAllocator;
    class MemoryAllocation;
}  // namespace gpgmm

namespace gpgmm { namespace d3d12 {

    class Heap;
    class ResidencyManager;
    class ResourceAllocation;
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

    typedef enum ALLOCATOR_RECORD_FLAGS {

        // Disables all recording flags. Enabled by default.
        ALLOCATOR_RECORD_FLAGS_NONE = 0x0,

        // Configures event-based tracing using the Trace Event API.
        ALLOCATOR_RECORD_TRACE_EVENTS = 0x1,

    } ALLOCATOR_RECORD_FLAGS;

    struct ALLOCATOR_RECORD_OPTIONS {
        ALLOCATOR_RECORD_FLAGS Flags = ALLOCATOR_RECORD_FLAGS_NONE;

        // Path to trace file. Default is trace.json.
        const char* TraceFile = nullptr;
    };

    struct ALLOCATOR_DESC {
        // Device and adapter used by this allocator. The adapter must support DXGI 1.4
        // to use residency. Required parameters.
        Microsoft::WRL::ComPtr<ID3D12Device> Device;
        Microsoft::WRL::ComPtr<IDXGIAdapter> Adapter;

        ALLOCATOR_FLAGS Flags = ALLOCATOR_FLAG_NONE;

        // Configures memory tracing.
        ALLOCATOR_RECORD_OPTIONS RecordOptions;

        // Determines if resource heaps can exist in shared memory. Use CheckFeatureSupport
        // to check for support. Required parameter.
        bool IsUMA;

        // Determines if resource heaps can mix resource categories (both texture and
        // buffers). Use CheckFeatureSupport to get supported tier. Required parameter.
        uint32_t ResourceHeapTier;

        // Preferred size of the resource heap.
        // The preferred size of the resource heap is the minimum heap size to sub-allocate
        // from. A larger resource heap consumes more memory but could be faster for sub-allocation.
        uint64_t PreferredResourceHeapSize;

        // Maximum size of the resource heap.
        // The maximum resource size restricts the total address range of available memory to
        // allocate.
        uint64_t MaxResourceHeapSize;

        // Maximum resource size allowed to be pool-allocated.
        // Pool-allocating larger resources consumes more memory but could be faster to allocate
        // from by using a pool of resource heaps.
        uint64_t MaxResourceSizeForPooling;

        // Maximum video memory available to budget by the allocator, expressed as a
        // percentage. By default, the max video memory available is 0.95 or 95% of video memory
        // can be budgeted, always leaving 5% for the OS and other applications.
        float MaxVideoMemoryBudget;

        // Total memory available to budget for resources created by this allocator.
        uint64_t TotalResourceBudgetLimit;

        // Total memory Size of resident resources that could be evicted, should there not be enough
        // residency budget available.
        uint64_t ResidentResourceEvictSize;
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

    class ResourceAllocator : public AllocatorBase, public IUnknownImpl {
      public:
        static HRESULT CreateAllocator(const ALLOCATOR_DESC& descriptor,
                                       ResourceAllocator** resourceAllocationOut);

        ~ResourceAllocator() override;

        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialResourceState,
                               const D3D12_CLEAR_VALUE* clearValue,
                               ResourceAllocation** resourceAllocationOut);

        HRESULT CreateResource(ComPtr<ID3D12Resource> committedResource,
                               ResourceAllocation** resourceAllocationOut);

        ResidencyManager* GetResidencyManager() const;

      private:
        friend ResourceHeapAllocator;
        friend ResourceAllocation;

        ResourceAllocator(ComPtr<ID3D12Device> device,
                          std::unique_ptr<ResidencyManager> residencyManager,
                          bool isUMA,
                          uint32_t resourceHeapTier,
                          ALLOCATOR_FLAGS allocatorFlags,
                          uint64_t maxResourceSizeForPooling,
                          uint64_t minResourceHeapSize,
                          uint64_t maxResourceHeapSize);

        HRESULT CreatePlacedResource(const MemoryAllocation& subAllocation,
                                     const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo,
                                     const D3D12_RESOURCE_DESC* resourceDescriptor,
                                     const D3D12_CLEAR_VALUE* clearValue,
                                     D3D12_RESOURCE_STATES initialResourceState,
                                     ResourceAllocation** resourceAllocationOut);

        HRESULT CreateCommittedResource(D3D12_HEAP_TYPE heapType,
                                        D3D12_HEAP_FLAGS heapFlags,
                                        const D3D12_RESOURCE_ALLOCATION_INFO& resourceInfo,
                                        const D3D12_RESOURCE_DESC* resourceDescriptor,
                                        const D3D12_CLEAR_VALUE* clearValue,
                                        D3D12_RESOURCE_STATES initialResourceState,
                                        ResourceAllocation** resourceAllocationOut);

        HRESULT CreateResourceHeap(uint64_t size,
                                   D3D12_HEAP_TYPE heapType,
                                   D3D12_HEAP_FLAGS heapFlags,
                                   uint64_t heapAlignment,
                                   Heap** resourceHeapOut);

        void FreeResourceHeap(Heap* resourceHeap);

        ComPtr<ID3D12Device> mDevice;
        std::unique_ptr<ResidencyManager> mResidencyManager;

        bool mIsUMA;
        uint32_t mResourceHeapTier;
        bool mIsAlwaysCommitted;
        bool mIsAlwaysInBudget;
        uint64_t mMaxResourceHeapSize;

        std::array<std::unique_ptr<MemoryAllocator>, ResourceHeapKind::EnumCount> mSubAllocators;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
