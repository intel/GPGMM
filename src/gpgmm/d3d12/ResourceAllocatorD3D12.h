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

#include "gpgmm/Allocator.h"
#include "gpgmm/common/Flags.h"
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "include/gpgmm_export.h"

#include <array>
#include <memory>
#include <string>

namespace gpgmm {
    class MemoryAllocator;
}  // namespace gpgmm

namespace gpgmm { namespace d3d12 {

    class BufferAllocator;
    class Heap;
    class ResidencyManager;
    class ResourceAllocation;
    class ResourceHeapAllocator;

    enum ALLOCATOR_FLAGS {

        // Disables all allocator flags. Enabled by default.
        ALLOCATOR_FLAG_NONE = 0x0,

        // Forces standalone committed resource creation. Useful to debug problems with
        // suballocation or needing to create very big resources.
        ALLOCATOR_FLAG_ALWAYS_COMMITED = 0x1,

        // Ensures resources are always within the resource budget at creation time. Mostly used
        // to debug with residency being over committed.
        ALLOCATOR_FLAG_ALWAYS_IN_BUDGET = 0x2,

    };

    using ALLOCATOR_FLAGS_TYPE = Flags<ALLOCATOR_FLAGS>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATOR_FLAGS_TYPE)

    enum ALLOCATOR_MESSAGE_SEVERITY {
        ALLOCATOR_MESSAGE_SEVERITY_MESSAGE = 0,
        ALLOCATOR_MESSAGE_SEVERITY_INFO = 1,
        ALLOCATOR_MESSAGE_SEVERITY_WARNING = 2,
        ALLOCATOR_MESSAGE_SEVERITY_ERROR = 3,
    };

    enum ALLOCATOR_RECORD_FLAGS {

        // Disables all recording flags. Enabled by default.
        ALLOCATOR_RECORD_FLAG_NONE = 0x0,

        // Configures event-based tracing using the Trace Event API.
        ALLOCATOR_RECORD_FLAG_TRACE_EVENTS = 0x1,

    };

    using ALLOCATOR_RECORD_FLAGS_TYPE = Flags<ALLOCATOR_RECORD_FLAGS>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATOR_RECORD_FLAGS_TYPE)

    struct ALLOCATOR_RECORD_OPTIONS {
        // Flags used to control how the allocator will record.
        ALLOCATOR_RECORD_FLAGS_TYPE Flags = ALLOCATOR_RECORD_FLAG_NONE;

        // Minimum severity level to record messages. Messages with lower severity
        // will be ignored.
        ALLOCATOR_MESSAGE_SEVERITY MinLogLevel = ALLOCATOR_MESSAGE_SEVERITY_WARNING;

        // Path to trace file. Default is trace.json.
        std::string TraceFile;
    };

    struct ALLOCATOR_DESC {
        // Device and adapter used by this allocator.
        // If the adapter does not support DXGI 1.4, residency is not supported.
        // Required parameters. Use CreateDevice and EnumAdapters get the device and adapter,
        // respectively.
        Microsoft::WRL::ComPtr<ID3D12Device> Device;
        Microsoft::WRL::ComPtr<IDXGIAdapter> Adapter;

        ALLOCATOR_FLAGS_TYPE Flags = ALLOCATOR_FLAG_NONE;

        // Minimum severity level to log messages to console. Messages with lower severity
        // will be ignored.
        ALLOCATOR_MESSAGE_SEVERITY MinLogLevel = ALLOCATOR_MESSAGE_SEVERITY_WARNING;

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
        // Optional parameter. When 0 is specified, the API will automatically set the preferred
        // resource heap size to the default value of 4MB.
        uint64_t PreferredResourceHeapSize;

        // Maximum size of the resource heap.
        // The maximum resource size is equal to the total address range of available memory to
        // allocate resources.
        // Optional parameter. When 0 is specified, the API will automatically set the max
        // resource heap size to the default value of 32GB.
        uint64_t MaxResourceHeapSize;

        // Maximum size of resource that can be pool-allocated.
        // Pool-allocating larger resources consumes more memory then smaller ones but is faster to
        // create subsequent resources by using a pool of resource heaps. Apps must periodically
        // call Trim() to free unused pool-allocated resource heaps.
        // Optional parameter. When 0 is specified, the API will automatically disabling pooling.
        uint64_t MaxResourceSizeForPooling;

        // Maximum video memory available to budget by the allocator, expressed as a
        // percentage.
        // Optional parameter. When 0 is specified, the API will automatically set the max video
        // memory budget to 95%, leaving 5% for the OS and other applications.
        float MaxVideoMemoryBudget;

        // Total memory available to budget for resources created by this allocator.
        // Optional parameter. When 0 is specified, the API will not restrict the resource budget.
        uint64_t TotalResourceBudgetLimit;

        // Video memory to evict from residency in order to make more resource resident, should
        // there not be enough budget available.
        // Optional parameter. When 0 is specified, the API will automatically set the video memory
        // evict size to 50MB.
        uint64_t VideoMemoryEvictSize;
    };

    enum ALLOCATION_FLAGS {

        // Disables all allocation flags. Enabled by default.
        ALLOCATION_FLAG_NONE = 0x0,

        // Forbids creating a new resource heap when creating a resource. The created resource
        // must use an existing resource heap or E_OUTOFMEMORY. Effectively disables creating
        // standalone allocations whose memory cannot be reused.
        ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY = 0x1,

        // Sub-allocate a resource allocation within the same resource. The resource alignment
        // is allowed to be byte-aligned instead of always being page-aligned, which significantly
        // reduces app memory usage. However, this is mostly limited for constant buffers (ie.
        // index and vertex buffers) which will be used as read-only after creation since the
        // resource can only be in one state at a time.
        // It is undefined behavior to use sub-allocations within the same resource betweem multiple
        // command queues since accesses are not guarenteed to be coherent.
        ALLOCATION_FLAG_SUBALLOCATE_WITHIN_RESOURCE = 0x2,

        // Forbids allowing multiple resource allocations to be created from the same resource
        // heap. The created resource will always be allocated with it's own resource heap.
        ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY = 0x4,

    };

    using ALLOCATION_FLAGS_TYPE = Flags<ALLOCATION_FLAGS>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATION_FLAGS_TYPE)

    struct ALLOCATION_DESC {
        // Flags used to control how the resource will be allocated.
        ALLOCATION_FLAGS_TYPE Flags = ALLOCATION_FLAG_NONE;

        // Heap type that the resource to be allocated requires.
        D3D12_HEAP_TYPE HeapType = D3D12_HEAP_TYPE_DEFAULT;
    };

    struct CREATE_RESOURCE_DESC {
        const ALLOCATION_DESC& allocationDescriptor;
        const D3D12_RESOURCE_DESC& resourceDescriptor;
        D3D12_RESOURCE_STATES initialResourceState;
        const D3D12_CLEAR_VALUE* clearValue;
    };

    struct QUERY_RESOURCE_ALLOCATOR_INFO {
        uint32_t UsedBlockCount;
        uint64_t UsedBlockUsage;
        uint32_t UsedResourceHeapCount;
        uint64_t UsedResourceHeapUsage;
    };

    enum ALLOCATOR_MESSAGE_ID {
        // D3D12 rejected the resource alignment specified.
        // The alignment value could be incorrect or use a resource that is unsupported by the
        // driver.
        ALLOCATOR_MESSAGE_ID_RESOURCE_ALIGNMENT_REJECTED = 0x0,

        // Suballocation was requested but did not succeed.
        // Suballocation failure occurs when the resource or heap size are misaligned.
        ALLOCATOR_MESSAGE_ID_RESOURCE_SUBALLOCATION_FAILED = 0x1,

        // D3D12 heap was created with a size that is not a multiple of the alignment, which wastes
        // memory unknowingly. D3D12 only supports misaligned heap sizes for convenience.
        ALLOCATOR_MESSAGE_ID_RESOURCE_HEAP_SUBOPTIMAL_ALIGNMENT = 0x2,

        // D3D12 resource was created with a size that is larger then alignment, which wastes memory
        // unknowingly. D3D12 only supports a resource size that is a multiple of 64KB.
        ALLOCATOR_MESSAGE_ID_RESOURCE_SUBOPTIMAL_ALIGNMENT = 0x3,

        // Resource allocation size exceeds the D3D12 resource size, which wastes memory
        // unknowingly. The allocator did not support allocation of a block equal to the resource
        // size.
        ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_SUBOPTIONAL_ALIGNMENT = 0x4,

        // Resource allocation was unable to be pool-allocated. This introduces OS VidMM overhead
        // because non-pool allocated memory cannot be reused by the allocator.
        ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_NON_POOLED = 0x5,

        // Resource allocator failed to allocate memory for the resource.
        ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_FAILED = 0x6,
    };

    struct ALLOCATOR_MESSAGE {
        std::string Description;
        ALLOCATOR_MESSAGE_ID ID;
    };

    class GPGMM_EXPORT ResourceAllocator final : public AllocatorBase, public IUnknownImpl {
      public:
        // Creates the allocator and residency manager instance used to manage video memory for the
        // App specified device and adapter. Residency manager only exists if this adapter at-least
        // supports DXGI 1.4 and cannot outlive the resource allocator used to create it.
        static HRESULT CreateAllocator(const ALLOCATOR_DESC& descriptor,
                                       ResourceAllocator** resourceAllocatorOut,
                                       ResidencyManager** residencyManagerOut = nullptr);

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

        // When pooling is enabled, the allocator will retain resource heaps in order to speed-up
        // subsequent resource allocation requests. These resource allocations count against the
        // app's memory usage and in general, will lead to increased memory usage by the overall
        // system. Apps should call Trim() when going idle for a period of time since there is a
        // brief performance hit when the internal resource heaps get reallocated by the OS.
        void Trim();

        // Informs the app of the current allocator usage.
        // If the allocator info is nullptr, info will only be recorded for trace.
        HRESULT QueryResourceAllocatorInfo(
            QUERY_RESOURCE_ALLOCATOR_INFO* resorceAllocationInfoOut = nullptr) const;

      private:
        friend BufferAllocator;
        friend ResourceHeapAllocator;
        friend ResourceAllocation;

        ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                          ComPtr<ResidencyManager> residencyManager);

        HRESULT CreatePlacedResource(Heap* const resourceHeap,
                                     uint64_t resourceOffset,
                                     const D3D12_RESOURCE_DESC* resourceDescriptor,
                                     const D3D12_CLEAR_VALUE* clearValue,
                                     D3D12_RESOURCE_STATES initialResourceState,
                                     ID3D12Resource** placedResourceOut);

        HRESULT CreateCommittedResource(D3D12_HEAP_TYPE heapType,
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
        ComPtr<ResidencyManager> mResidencyManager;

        const bool mIsUMA;
        const D3D12_RESOURCE_HEAP_TIER mResourceHeapTier;
        const bool mIsAlwaysCommitted;
        const bool mIsAlwaysInBudget;
        const uint64_t mMaxResourceHeapSize;

        static constexpr uint64_t kNumOfResourceHeapTypes = 8u;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceHeapAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceSubAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mBufferSubAllocatorOfType;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
