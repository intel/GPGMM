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
    class MemoryPool;
}  // namespace gpgmm

namespace gpgmm { namespace d3d12 {

    class BufferAllocator;
    class Heap;
    class ResidencyManager;
    class ResourceAllocation;
    class ResourceHeapAllocator;

    typedef enum ALLOCATOR_FLAGS {

        // Disables all allocator flags. Enabled by default.
        ALLOCATOR_FLAG_NONE = 0x0,

        // Forces standalone committed resource creation. Useful to debug problems with
        // suballocation or needing to create very big resources.
        ALLOCATOR_FLAG_ALWAYS_COMMITED = 0x1,

        // Ensures resources are always within the resource budget at creation time. Mostly used
        // to debug with residency being over committed.
        ALLOCATOR_FLAG_ALWAYS_IN_BUDGET = 0x2,

    } ALLOCATOR_FLAGS;

    typedef enum ALLOCATOR_RECORD_FLAGS {

        // Disables all recording flags. Enabled by default.
        ALLOCATOR_RECORD_FLAG_NONE = 0x0,

        // Configures event-based tracing using the Trace Event API.
        ALLOCATOR_RECORD_FLAG_TRACE_EVENTS = 0x1,

    } ALLOCATOR_RECORD_FLAGS;

    struct ALLOCATOR_RECORD_OPTIONS {
        ALLOCATOR_RECORD_FLAGS Flags = ALLOCATOR_RECORD_FLAG_NONE;

        // Path to trace file. Default is trace.json.
        const char* TraceFile = nullptr;
    };

    struct ALLOCATOR_DESC {
        // Device and adapter used by this allocator. The adapter must support DXGI 1.4
        // to use residency.
        // Required parameters. Use CreateDevice and EnumAdapters get the device and adapter,
        // respectively.
        Microsoft::WRL::ComPtr<ID3D12Device> Device;
        Microsoft::WRL::ComPtr<IDXGIAdapter> Adapter;

        ALLOCATOR_FLAGS Flags = ALLOCATOR_FLAG_NONE;

        // Configures memory tracing.
        ALLOCATOR_RECORD_OPTIONS RecordOptions;

        // Determines if resource heaps can exist in shared memory.
        // Required parameter. Use CheckFeatureSupport to determine if supported.
        bool IsUMA;

        // Determines if resource heaps can mix resource categories (both texture and
        // buffers).
        // Required parameter. Use CheckFeatureSupport to get supported tier.
        D3D12_RESOURCE_HEAP_TIER ResourceHeapTier;

        // Preferred size of the resource heap.
        // The preferred size of the resource heap is the minimum heap size to sub-allocate
        // from. A larger resource heap consumes more memory but could be faster for sub-allocation.
        // Optional parameter. When 0 is used, the API will automatically set the preferred
        // resource heap size to the default value of 4MB.
        uint64_t PreferredResourceHeapSize;

        // Maximum size of the resource heap.
        // The maximum resource size restricts the total address range of available memory to
        // allocate.
        // Optional parameter. When 0 is used, the API will automatically set the max
        // resource heap size to the default value of 32GB.
        uint64_t MaxResourceHeapSize;

        // Maximum resource size allowed to be pool-allocated.
        // Pool-allocating larger resources consumes more memory but could be faster to allocate
        // from by using a pool of resource heaps.
        // Optional parameter. When 0 is used, the API will automatically disabling pooling.
        uint64_t MaxResourceSizeForPooling;

        // Maximum video memory available to budget by the allocator, expressed as a
        // percentage.
        // Optional parameter. When 0 is used, the API will automatically set the max video memory
        // budget to 95%, leaving 5% for the OS and other applications.
        float MaxVideoMemoryBudget;

        // Total memory available to budget for resources created by this allocator.
        // Optional parameter. When 0 is used, the API will not restrict the resource budget.
        uint64_t TotalResourceBudgetLimit;

        // Total memory Size of resident resources that could be evicted, should there not be enough
        // residency budget available.
        // Optional parameter. When 0 is used, the API will try to evict 50MB worth of resource
        // memory before re-attempting to make them resident.
        uint64_t ResidentResourceEvictSize;
    };

    typedef enum ALLOCATION_FLAGS {

        // Disables all allocation flags. Enabled by default.
        ALLOCATION_FLAG_NONE = 0x0,

        // Forbids creating a new resource heap when creating a resource. The created resource
        // must use an existing resource heap or E_OUTOFMEMORY. Effectively disables creating
        // standalone allocations whose memory cannot be reused.
        ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY = 0x1,

        // Sub-allocates within the same resource down to a single byte. This is useful
        // for constant buffers (ie. index and vertex buffers) which will be used as read-only
        // after creation since the resource can only be in one state at a time. When this
        // flag is not used, the minimum resource size is always equal to the smallest resource heap
        // allowed (or 64KB).
        // It is undefined behavior to use sub-allocations within the same resource betweem multiple
        // command queues since accesses are not guarenteed to be coherent.
        ALLOCATION_FLAG_SUBALLOCATE_WITHIN_RESOURCE = 0x2,

    } ALLOCATION_FLAGS;

    struct ALLOCATION_DESC {
        ALLOCATION_FLAGS Flags = ALLOCATION_FLAG_NONE;
        D3D12_HEAP_TYPE HeapType = D3D12_HEAP_TYPE_DEFAULT;
    };

    typedef enum RESOURCE_HEAP_TYPE {

        // Resource heap tier 2
        // Resource heaps contain all buffer and textures types.
        RESOURCE_HEAP_TYPE_READBACK_ALLOW_ALL_BUFFERS_AND_TEXTURES = 0x0,
        RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ALL_BUFFERS_AND_TEXTURES = 0x1,
        RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ALL_BUFFERS_AND_TEXTURES = 0x2,

        // Resource heap tier 1
        // Resource heaps contain buffers or textures but not both.
        RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_BUFFERS = 0x3,
        RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_BUFFERS = 0x4,
        RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_BUFFERS = 0x5,

        RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES = 0x6,
        RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES = 0x7,

        ENUMCOUNT,
        INVALID = ENUMCOUNT,
    } RESOURCE_HEAP_TYPE;

    class ResourceAllocator final : public AllocatorBase, public IUnknownImpl {
      public:
        // Creates the main instance used to help manage video memory for the
        // specified D3D12 device and adapter in the |descriptor|.
        static HRESULT CreateAllocator(const ALLOCATOR_DESC& descriptor,
                                       ResourceAllocator** resourceAllocationOut);

        ~ResourceAllocator() override;

        // Allocates memory and creates a D3D12 resource using it.
        // Returns a ResourceAllocation which represents a resource allocated at a specific
        // location in memory. The resource could be allocated within a resource heap, within the
        // resource itself, or seperately using it's own memory (resource heap). Unlike a D3D12
        // resource, a resource allocation can made resident. It is recommended but not strictly
        // required to use the D3D12 resource equivalent methods (ex. Map, Unmap) through the
        // returned ResourceAllocation.
        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialResourceState,
                               const D3D12_CLEAR_VALUE* clearValue,
                               ResourceAllocation** resourceAllocationOut);

        // Imports an existing D3D12 resource. Allows externally created D3D12 resources to be used
        // as ResourceAllocations. Residency is not supported for imported resources.
        HRESULT CreateResource(ComPtr<ID3D12Resource> committedResource,
                               ResourceAllocation** resourceAllocationOut);

        // Return the residency manager. The lifetime of the residency manager is fully owned by the
        // allocator. CreateResource enables the returned resource allocation to be residency
        // managed when non-null.
        ResidencyManager* GetResidencyManager() const;

      protected:
        void DeleteThis() override;

      private:
        friend BufferAllocator;
        friend ResourceHeapAllocator;
        friend ResourceAllocation;

        ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                          std::unique_ptr<ResidencyManager> residencyManager);

        HRESULT CreatePlacedResourceHeap(const MemoryAllocation& subAllocation,
                                         const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo,
                                         const D3D12_RESOURCE_DESC* resourceDescriptor,
                                         const D3D12_CLEAR_VALUE* clearValue,
                                         D3D12_RESOURCE_STATES initialResourceState,
                                         ID3D12Resource** placedResourceOut,
                                         Heap** resourceHeapOut);

        HRESULT CreateCommittedResourceHeap(D3D12_HEAP_TYPE heapType,
                                            D3D12_HEAP_FLAGS heapFlags,
                                            uint64_t resourceSize,
                                            const D3D12_RESOURCE_DESC* resourceDescriptor,
                                            const D3D12_CLEAR_VALUE* clearValue,
                                            D3D12_RESOURCE_STATES initialResourceState,
                                            ID3D12Resource** commitedResourceOut,
                                            Heap** resourceHeapOut);

        HRESULT CreateResourceHeap(uint64_t heapSize,
                                   D3D12_HEAP_TYPE heapType,
                                   D3D12_HEAP_FLAGS heapFlags,
                                   uint64_t heapAlignment,
                                   Heap** resourceHeapOut);

        void FreeResourceHeap(Heap* resourceHeap);

        ComPtr<ID3D12Device> mDevice;
        std::unique_ptr<ResidencyManager> mResidencyManager;

        const bool mIsUMA;
        const D3D12_RESOURCE_HEAP_TIER mResourceHeapTier;
        const bool mIsAlwaysCommitted;
        const bool mIsAlwaysInBudget;
        const uint64_t mMaxResourceHeapSize;

        std::array<std::unique_ptr<MemoryPool>, RESOURCE_HEAP_TYPE::ENUMCOUNT>
            mResourceHeapPoolOfType;
        std::array<std::unique_ptr<MemoryAllocator>, RESOURCE_HEAP_TYPE::ENUMCOUNT>
            mResourceHeapSubAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, RESOURCE_HEAP_TYPE::ENUMCOUNT>
            mBufferSubAllocatorOfType;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
