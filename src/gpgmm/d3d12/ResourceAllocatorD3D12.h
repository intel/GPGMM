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

#include "gpgmm/MemoryAllocator.h"
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
    class Caps;
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

        // Checks for leaked device objects created by GPGMM.
        // Requires the debug layers to be enabled by installing Graphics Tools in Windows and
        // calling EnableDebugLayer before creation.
        // Will assert if a leak is detected during destruction.
        ALLOCATOR_CHECK_DEVICE_LEAKS = 0x4,
    };

    using ALLOCATOR_FLAGS_TYPE = Flags<ALLOCATOR_FLAGS>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATOR_FLAGS_TYPE)

    enum ALLOCATOR_MESSAGE_SEVERITY {
        ALLOCATOR_MESSAGE_SEVERITY_MESSAGE = 0x0,
        ALLOCATOR_MESSAGE_SEVERITY_INFO = 0x1,
        ALLOCATOR_MESSAGE_SEVERITY_WARNING = 0x2,
        ALLOCATOR_MESSAGE_SEVERITY_ERROR = 0x3,
    };

    enum ALLOCATOR_RECORD_FLAGS {

        // Record nothing. Enabled by default.
        ALLOCATOR_RECORD_FLAG_NONE = 0x0,

        // Record lifetimes of API objects created by GPGMM.
        ALLOCATOR_RECORD_FLAG_API_OBJECTS = 0x1,

        // Record calls made to GPGMM API.
        ALLOCATOR_RECORD_FLAG_API_CALLS = 0x2,

        // Record duration of GPGMM API calls.
        ALLOCATOR_RECORD_FLAG_API_TIMINGS = 0x4,

        // Aliases that combine flags per activity.
        ALLOCATOR_RECORD_FLAG_CAPTURE = 0x3,
        ALLOCATOR_RECORD_FLAG_PROFILE = 0x4,

        // Record everything.
        ALLOCATOR_RECORD_FLAG_ALL_EVENTS = 0xFF,
    };

    using ALLOCATOR_RECORD_FLAGS_TYPE = Flags<ALLOCATOR_RECORD_FLAGS>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATOR_RECORD_FLAGS_TYPE)

    struct ALLOCATOR_RECORD_OPTIONS {
        // Flags used to decide what to record.
        ALLOCATOR_RECORD_FLAGS_TYPE Flags = ALLOCATOR_RECORD_FLAG_NONE;

        // Minimum severity level to record messages. Messages with lower severity
        // will be ignored.
        ALLOCATOR_MESSAGE_SEVERITY MinMessageLevel = ALLOCATOR_MESSAGE_SEVERITY_WARNING;

        // Path to trace file. Default is trace.json.
        std::string TraceFile;
    };

    struct ALLOCATOR_DESC {
        // Specifies the device and adapter used by this allocator. Use CreateDevice and
        // EnumAdapters to get the device and adapter, respectively.
        Microsoft::WRL::ComPtr<ID3D12Device> Device;
        Microsoft::WRL::ComPtr<IDXGIAdapter> Adapter;

        // Specifies allocator options, such as wheather the allocator can sub-allocate or not, and
        // whether resources should be resident upon creation.
        ALLOCATOR_FLAGS_TYPE Flags = ALLOCATOR_FLAG_NONE;

        // Minimum severity level to log messages to console. Messages with lower severity
        // will be ignored.
        ALLOCATOR_MESSAGE_SEVERITY MinLogLevel = ALLOCATOR_MESSAGE_SEVERITY_WARNING;

        // Specifies recording options, such as what events to record, and where to record them.
        ALLOCATOR_RECORD_OPTIONS RecordOptions;

        // Supports unified memory architecture.
        //
        // Used to determine if resource heaps can exist in shared memory.
        //
        // Required parameter. Use CheckFeatureSupport to determine if supported.
        bool IsUMA;

        // Adapter's tier of resource heap support.
        //
        // Used to determine if resource categories (both texture and buffers) can co-exist in the
        // same resource heap.
        //
        // Required parameter. Use CheckFeatureSupport to get supported tier.
        D3D12_RESOURCE_HEAP_TIER ResourceHeapTier;

        // Preferred size of the resource heap.
        //
        // The preferred size of the resource heap is the minimum heap size to sub-allocate
        // from. A larger resource heap consumes more memory but could be faster for sub-allocation.
        //
        // Optional parameter. When 0 is specified, the API will automatically set the preferred
        // resource heap size to the default value of 4MB.
        uint64_t PreferredResourceHeapSize;

        // Maximum size of the resource heap.
        //
        // The maximum resource heap size is equal to the total virtual address range of available
        // memory used to allocate resources.
        //
        // Optional parameter. When 0 is specified, the API will automatically set the max resource
        // heap size based on the adapter's GPU virtual address range. If the max resource size
        // exceeds the adapter's GPU virtual address range, it will default to the smaller range.
        uint64_t MaxResourceHeapSize;

        // Maximum resource size that can be pool-allocated.
        //
        // Pool-allocating larger resources consumes more memory then smaller ones but is faster to
        // create subsequent resources by using a pool of resource heaps. Apps must periodically
        // call Trim() to free unused pool-allocated resource heaps.
        //
        // Optional parameter. When 0 is specified, the API will automatically disabling pooling.
        uint64_t MaxResourceSizeForPooling;

        // Maximum video memory available to budget by the allocator, expressed as a
        // percentage.
        //
        // Optional parameter. When 0 is specified, the API will automatically set the max video
        // memory budget to 95%, leaving 5% for the OS and other applications.
        float MaxVideoMemoryBudget;

        // Total memory available to budget for resources.
        //
        // Optional parameter. When 0 is specified, the API will not restrict the resource budget.
        uint64_t TotalResourceBudgetLimit;

        // Video memory to evict from residency in order to make more resource resident, should
        // there not be enough budget available.
        //
        // Optional parameter. When 0 is specified, the API will automatically set the video memory
        // evict size to 50MB.
        uint64_t VideoMemoryEvictSize;

        // Resource fragmentation limit, expressed as a percentage of the resource heap size, that
        // is acceptable to be wasted due to internal fragmentation.
        //
        // Internal fragmentation is when the resource allocation size is larger then the resource
        // size requested. This occurs when the type of resource (buffer or texture) and
        // sub-allocation algorithm (buddy, slab, etc) have different alignment requirements. For
        // example, a 192KB page-aligned resource may need to allocate 256KB of binary-allocated
        // space, which if allowed, has a fragmentation limit of 1/3rd.
        // When |PreferredResourceHeapSize| is non-zero, |ResourceFragmentationLimit| could be
        // exceeded.
        //
        // Optional parameter. When 0 is specified, the API will automatically set the resource
        // fragmentation limit to 1/8th the resource heap size.
        double ResourceFragmentationLimit;
    };

    enum ALLOCATION_FLAGS {

        // Disables all allocation flags. Enabled by default.
        ALLOCATION_FLAG_NONE = 0x0,

        // Forbids creating a new resource heap when creating a resource. The created resource
        // must use an existing resource heap or E_OUTOFMEMORY. Effectively disables creating
        // standalone allocations whose memory cannot be reused.
        ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY = 0x1,

        // Sub-allocate a resource allocation within the same resource. The resource alignment
        // is allowed to be byte-aligned instead of being resource-aligned, which significantly
        // reduces app memory usage (1B vs 64KB per allocation). Since the resource can only be in
        // one state at a time, this is mostly restricted for constant buffers (index and vertex
        // buffers) which will stay read-only after creation. This flag is automatically
        // enabled for devices that already guarentee command queue accesses are always coherent
        // between sub-allocations within the same resource.
        ALLOCATION_FLAG_ALWAYS_SUBALLOCATE_WITHIN_RESOURCE = 0x2,

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

    using QUERY_RESOURCE_ALLOCATOR_INFO = MEMORY_ALLOCATOR_INFO;

    enum ALLOCATOR_MESSAGE_ID {

        ALLOCATOR_MESSAGE_ID_UNKNOWN,

        // D3D12 heap was created with a size that is not a multiple of the alignment, which wastes
        // memory unknowingly. D3D12 only supports misaligned heap sizes for convenience.
        ALLOCATOR_MESSAGE_ID_RESOURCE_HEAP_MISALIGNMENT,

        // D3D12 resource was created with a size using a multiple of much larger alignment than
        // requested.
        ALLOCATOR_MESSAGE_ID_RESOURCE_MISALIGNMENT,

        // Resource allocation size exceeds the D3D12 resource size, which wastes memory
        // unknowingly. The allocator did not support allocation of a block equal to the resource
        // size.
        ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_MISALIGNMENT,

        // Resource allocation was unable to be pool-allocated. This introduces OS VidMM overhead
        // because non-pool allocated memory cannot be reused by the allocator.
        ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_NON_POOLED,

        // Resource allocator failed to allocate memory for the resource.
        ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATOR_FAILED,
    };

    struct ALLOCATOR_MESSAGE {
        std::string Description;
        ALLOCATOR_MESSAGE_ID ID;
    };

    class GPGMM_EXPORT ResourceAllocator final : public MemoryAllocator, public IUnknownImpl {
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
            QUERY_RESOURCE_ALLOCATOR_INFO* resourceAllocationInfoOut = nullptr) const;

      private:
        friend BufferAllocator;
        friend ResourceHeapAllocator;
        friend ResourceAllocation;

        ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                          ComPtr<ResidencyManager> residencyManager,
                          std::unique_ptr<Caps> caps);

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

        HRESULT EnableDeviceObjectLeakChecks() const;
        HRESULT CheckForDeviceObjectLeaks() const;

        // MemoryAllocator interface
        void DeallocateMemory(MemoryAllocation* allocation) override;

        ComPtr<ID3D12Device> mDevice;
        ComPtr<ResidencyManager> mResidencyManager;

        std::unique_ptr<Caps> mCaps;

        const bool mIsUMA;
        const D3D12_RESOURCE_HEAP_TIER mResourceHeapTier;
        const bool mIsAlwaysCommitted;
        const bool mIsAlwaysInBudget;
        const uint64_t mMaxResourceHeapSize;
        const uint64_t mMaxResourceSizeForPooling;

        static constexpr uint64_t kNumOfResourceHeapTypes = 8u;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceHeapAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mBufferAllocatorOfType;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
