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
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "gpgmm/utils/Flags.h"
#include "include/gpgmm_export.h"


#include <array>
#include <memory>
#include <string>

namespace gpgmm {
    class MemoryAllocator;
    class PlatformTime;
}  // namespace gpgmm

namespace gpgmm { namespace d3d12 {

    class BufferAllocator;
    class Caps;
    class Heap;
    class DebugResourceAllocator;
    class ResidencyManager;
    class ResourceAllocation;

    enum ALLOCATOR_FLAGS {

        /** \brief Disables all allocator flags.
         */
        ALLOCATOR_FLAG_NONE = 0x0,

        /** \brief Disable reuse of resource memory.

        Should only be used for debugging and testing purposes.
        */
        ALLOCATOR_FLAG_ALWAYS_COMMITED = 0x1,

        /** \brief Ensures resources are always within the resource budget at creation time.

        Mostly used to debug with residency being over committed.
        */
        ALLOCATOR_FLAG_ALWAYS_IN_BUDGET = 0x2,

        /** \brief Disables pre-fetching of GPU memory.

        Should be only used for debugging and testing purposes.
        */
        ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH = 0x4,

        /** \brief Tell GPGMM to allocate exactly what is needed, and to de-allocate
        memory immediately once no longer needed (instead of re-using it).

        This is very slow and not recommended for general use but may be useful for running with the
        minimal possible GPU memory footprint or debugging OOM failures.
        */
        ALLOCATOR_FLAG_ALWAYS_ON_DEMAND = 0x8,

        /** \brief Flags no longer used and will soon be depreciated.
         */
        ALLOCATOR_CHECK_DEVICE_LEAKS = 0x16,
    };

    using ALLOCATOR_FLAGS_TYPE = Flags<ALLOCATOR_FLAGS>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATOR_FLAGS_TYPE)

    /** \enum ALLOCATOR_MESSAGE_SEVERITY
    Represents different severity levels used for logging.
    */
    enum ALLOCATOR_MESSAGE_SEVERITY {
        /** \brief Message (or debug) severity.

        Message is for debugging purposes only.
        */
        ALLOCATOR_MESSAGE_SEVERITY_MESSAGE = 0x0,

        /** \brief Info severity.

        Message is for informational purposes only.
        */
        ALLOCATOR_MESSAGE_SEVERITY_INFO = 0x1,

        /** \brief Warning severity.

        A non-fatal message that does not abort execution.
        */
        ALLOCATOR_MESSAGE_SEVERITY_WARNING = 0x2,

        /** \brief Error severity.

        A fatal message will abort execution.
        */
        ALLOCATOR_MESSAGE_SEVERITY_ERROR = 0x3,
    };

    /** \enum ALLOCATOR_RECORD_FLAGS
    Represents different event categories to record.
    */
    enum ALLOCATOR_RECORD_FLAGS {

        /** \brief Record nothing.
         */
        ALLOCATOR_RECORD_FLAG_NONE = 0x0,

        /** \brief Record lifetimes of API objects created by GPGMM.
         */
        ALLOCATOR_RECORD_FLAG_API_OBJECTS = 0x1,

        /** \brief Record API calls made to GPGMM.
         */
        ALLOCATOR_RECORD_FLAG_API_CALLS = 0x2,

        /** \brief Record duration of GPGMM API calls.
         */
        ALLOCATOR_RECORD_FLAG_API_TIMINGS = 0x4,

        /** \brief Record events required for playback.

         Bitwise OR'd combination of ALLOCATOR_RECORD_FLAG_API_OBJECTS and
         ALLOCATOR_RECORD_FLAG_API_CALLS.
         */
        ALLOCATOR_RECORD_FLAG_CAPTURE = 0x3,

        /** \brief Record events required for profiling.

         Aliases or equal to ALLOCATOR_RECORD_FLAG_API_TIMINGS.
         */
        ALLOCATOR_RECORD_FLAG_PROFILE = 0x4,

        /** \brief Record everything.
         */
        ALLOCATOR_RECORD_FLAG_ALL_EVENTS = 0xFF,
    };

    using ALLOCATOR_RECORD_FLAGS_TYPE = Flags<ALLOCATOR_RECORD_FLAGS>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATOR_RECORD_FLAGS_TYPE)

    /** \enum ALLOCATOR_RECORD_SCOPE
    Represents recording scopes to limit event recording.
    */
    enum ALLOCATOR_RECORD_SCOPE {

        /** \brief Scopes events per process (or multiple allocators).
         */
        ALLOCATOR_RECORD_SCOPE_PER_PROCESS = 0x0,

        /** \brief Scopes events per allocator object.
         */
        ALLOCATOR_RECORD_SCOPE_PER_INSTANCE = 0x1,
    };

    using ALLOCATOR_RECORD_SCOPE_TYPE = Flags<ALLOCATOR_RECORD_SCOPE>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATOR_RECORD_SCOPE_TYPE)

    /** \struct ALLOCATOR_RECORD_OPTIONS
    Represents additional controls for recording.
    */
    struct ALLOCATOR_RECORD_OPTIONS {
        /** \brief Flags used to decide what to record.

        Optional parameter. By default, nothing is recorded.
        */
        ALLOCATOR_RECORD_FLAGS_TYPE Flags = ALLOCATOR_RECORD_FLAG_NONE;

        /** \brief Minimum severity level to record messages.

        Messages with lower severity will be ignored.

        Optional parameter. By default, the minimum severity level is WARN.
        */
        ALLOCATOR_MESSAGE_SEVERITY MinMessageLevel = ALLOCATOR_MESSAGE_SEVERITY_WARNING;

        /** \brief Specifies the scope of the events.

        Optional parameter. By default, recording is per process.
        */
        ALLOCATOR_RECORD_SCOPE EventScope = ALLOCATOR_RECORD_SCOPE_PER_PROCESS;

        /** \brief Path to trace file.

        Optional parameter. By default, a trace file is created for you.
        */
        std::string TraceFile;
    };

    /** \struct ALLOCATOR_DESC
    Specify parameters for creating allocators.
    */
    struct ALLOCATOR_DESC {
        /** \brief Specifies the device used by this allocator.

        Required parameter. Use CreateDevice get the device.
        */
        Microsoft::WRL::ComPtr<ID3D12Device> Device;

        /** \brief Specifies the adapter used by this allocator.

        Required parameter. Use EnumAdapters to get the adapter.
        */
        Microsoft::WRL::ComPtr<IDXGIAdapter> Adapter;

        /** \brief Specifies allocator options.

        For example, whether the allocator can reuse memory, or resources should be resident upon
        creation.
        */
        ALLOCATOR_FLAGS_TYPE Flags = ALLOCATOR_FLAG_NONE;

        /** \brief Minimum severity level to log messages to console.

        Messages with lower severity will be ignored.
        */
        ALLOCATOR_MESSAGE_SEVERITY MinLogLevel = ALLOCATOR_MESSAGE_SEVERITY_WARNING;

        /** \brief Specifies recording options.

        For example, what events to record, and where to record them.
        */
        ALLOCATOR_RECORD_OPTIONS RecordOptions;

        /** \brief Specifies if unified memory architecture (UMA) support is enabled.

        Used to determine if resource heaps can exist in shared memory.

        Required parameter. Use CheckFeatureSupport to determine if supported.
        */
        bool IsUMA;

        /** \brief Specifies the adapter's tier of resource heap support.

        Used to determine if resource categories (texture and buffers) can co-exist in the
        same resource heap.

        Required parameter. Use CheckFeatureSupport to get supported tier.
        */
        D3D12_RESOURCE_HEAP_TIER ResourceHeapTier;

        /** \brief Specifies the preferred size of the resource heap.

        The preferred size of the resource heap is the minimum heap size to sub-allocate from.
        A larger resource heap consumes more memory but could be faster for sub-allocation.

        Optional parameter. When 0 is specified, the API will automatically set the preferred
        resource heap size to the default value of 4MB.
        */
        uint64_t PreferredResourceHeapSize;

        /** \brief Maximum size of the resource heap allowed.

        The maximum resource heap size is equal to the total virtual address range of memory
        available to the allocator.

        Optional parameter. When 0 is specified, the API will automatically set the max resource
        heap size based on the adapter's GPU virtual address range. If the max resource size
        exceeds the adapter's GPU virtual address range, it will default to the smaller range.
        */
        uint64_t MaxResourceHeapSize;

        /** \brief Maximum video memory available to budget by the allocator, expressed as a
        percentage.

        Optional parameter. When 0 is specified, the API will automatically set the max video
        memory budget to 95%, leaving 5% for the OS and other applications.
        */
        float MaxVideoMemoryBudget;

        /** \brief Total memory available to budget for resources.

        Optional parameter. When 0 is specified, the API will not restrict the resource budget.
        */
        uint64_t TotalResourceBudgetLimit;

        /** \brief Total memory to evict from residency at once, should there not be enough budget
        left.

        Optional parameter. When 0 is specified, the API will automatically set the video memory
        evict size to 50MB.
        */
        uint64_t EvictLimit;

        /** \brief Memory fragmentation limit, expressed as a percentage of the resource heap size,
        that is acceptable to be wasted due to internal fragmentation.

        Internal fragmentation is when the resource allocation size is larger then the resource
        size requested. This occurs when the type of resource (buffer or texture) and
        sub-allocation algorithm (buddy, slab, etc) have different alignment requirements. For
        example, a 192KB page-aligned resource may need to allocate 256KB of binary-allocated
        space, which if allowed, has a fragmentation limit of 1/3rd.

        When |PreferredResourceHeapSize| is non-zero, |MemoryFragmentationLimit| could be
        exceeded.

        Optional parameter. When 0 is specified, the API will automatically set the resource
        fragmentation limit to 1/8th the resource heap size.
        */
        double MemoryFragmentationLimit;
    };

    /** \enum ALLOCATION_FLAGS
    Additional controls that modify allocations.
    */
    enum ALLOCATION_FLAGS {

        /** \brief Disables all allocation flags.

        Enabled by default.
        */
        ALLOCATION_FLAG_NONE = 0x0,

        /** \brief Disallow creating a new resource heap when creating a resource.

        The created resource must use an existing resource heap or E_OUTOFMEMORY. Effectively
        disables creating standalone allocations whose memory cannot be reused.
        */
        ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY = 0x1,

        /** \brief Sub-allocate a resource allocation within the same resource.

        The resource alignment is allowed to be byte-aligned instead of being resource-aligned,
        which significantly reduces app memory usage (1B vs 64KB per allocation). Since the resource
        can only be in one state at a time, this is mostly restricted to constant buffers (index and
        vertex buffers which will stay read-only after creation). The app developer must use offsets
        from the start of the allocation (vs subresource) by using GetOffsetFromResource().
        Since all devices guarentee command queue accesses are coherent between sub-allocations
        within the same resource. The app developer must check if the adapter is supported OR
        ensure only a command single queue is used.
        */
        ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE = 0x2,

        /** \brief Disallow creating multiple resource allocations from the same resource heap.

        The created resource will always be allocated with it's own resource heap.
        */
        ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY = 0x4,

        /** \brief Prefetch memory for the next resource allocation.

        The call to prefetch is deferred to a seperate background thread by GPGMM which runs
        when the current allocation requested is completed. By default, GPGMM will automatically
        trigger prefetching based on heurstics. Prefetching enables more performance when
        allocating for large contiguous allocations.

        Should not be used with ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY.
        */
        ALLOCATION_FLAG_ALWAYS_PREFETCH_MEMORY = 0x8,
    };

    using ALLOCATION_FLAGS_TYPE = Flags<ALLOCATION_FLAGS>;
    DEFINE_OPERATORS_FOR_FLAGS(ALLOCATION_FLAGS_TYPE)

    /** \struct ALLOCATION_FLAGS
    Specifies how allocations should be created.
    */
    struct ALLOCATION_DESC {
        /** \brief Flags used to control how the resource will be allocated.

        Optional parameter. By default, GPGMM will decide automatically.
        */
        ALLOCATION_FLAGS_TYPE Flags = ALLOCATION_FLAG_NONE;

        /** \brief Heap type that the resource to be allocated requires.

        Required parameter. GPGMM always initializes to D3D12_HEAP_TYPE_DEFAULT.
        */
        D3D12_HEAP_TYPE HeapType = D3D12_HEAP_TYPE_DEFAULT;
    };

    using RESOURCE_ALLOCATOR_INFO = MEMORY_ALLOCATOR_INFO;

    class GPGMM_EXPORT ResourceAllocator final : public MemoryAllocator, public IUnknownImpl {
      public:
        /** \brief  Create allocator and optional residency manager used to create and manage video
        memory for the App specified device and adapter.

        Residency manager only exists if this adapter at-least supports DXGI 1.4.

        @param descriptor A reference to ALLOCATOR_DESC structure that describes the allocator.
        @param[out] resourceAllocatorOut Pointer to a memory block that recieves a pointer to the
        resource allocator. Pass NULL to test if allocator creation would succeed, but not actually
        create the allocator. If NULL is passed and allocator creating would succeed, S_FALSE is
        returned.
        @param[out] residencyManagerOut Pointer to a memory block that recieves a pointer to the
        residency manager. Pass NULL to test if residency manager creation would succeed, but not
        actually create the residency manager. If NULL is passed and residency manager creation
        would succeed, S_FALSE is returned.
        */
        static HRESULT CreateAllocator(const ALLOCATOR_DESC& descriptor,
                                       ResourceAllocator** resourceAllocatorOut,
                                       ResidencyManager** residencyManagerOut = nullptr);

        ~ResourceAllocator() override;

        /** \brief  Allocates memory and creates a D3D12 resource using it.

        Returns a ResourceAllocation which represents a resource allocated at a specific
        location in memory. The resource could be allocated within a resource heap, within the
        resource itself, or seperately using it's own memory (resource heap).

        Unlike a D3D12 resource, a resource allocation can made resident. It is recommended but not
        strictly required to use the D3D12 resource equivalent methods (ex. Map, Unmap) through the
        returned ResourceAllocation.

        @param allocationDescriptor A reference to ALLOCATION_DESC structure that provides
        properties for the resource allocation.
        @param resourceDescriptor A reference to the D3D12_RESOURCE_DESC structure that describes
        the resource.
        @param initialResourceState The initial state of the resource, a bitwise OR'd combination of
        D3D12_RESOURCE_STATES enumeration constants.
        @param clearValue Specifies a D3D12_CLEAR_VALUE structure that describes the default value
        for a clear color.
        @param[out] resourceAllocationOut An optional pointer to a memory block that recieves the
        required interface pointer to the created resource allocation object.
        */
        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialResourceState,
                               const D3D12_CLEAR_VALUE* clearValue,
                               ResourceAllocation** resourceAllocationOut);

        /** \brief  Imports an existing D3D12 resource.

        Allows externally created D3D12 resources to be used as ResourceAllocations.
        Residency is not supported for imported resources.

        @param committedResource A COM managed pointer to a D3D12 committed resource.
        @param[out] resourceAllocationOut Pointer to a memory block that recieves a pointer to the
        resource allocation. Pass NULL to test if resource allocation creation would succeed, but
        not actually create the resource allocation. If NULL is passed and resource allocation
        creation would succeed, S_FALSE is returned.
        */
        HRESULT CreateResource(ComPtr<ID3D12Resource> committedResource,
                               ResourceAllocation** resourceAllocationOut);

        /** \brief Recycle resource heaps held internally by GPGMM.

        When pooling is enabled, the allocator will retain resource heaps in order to speed-up
        subsequent resource allocation requests. These resource allocations count against the
        app's memory usage and in general, will lead to increased memory usage by the overall
        system. Apps should call Trim() when going idle for a period of time since there is a
        brief performance hit when the internal resource heaps get reallocated by the OS.
        */
        void Trim();

        /** \brief  Return the current allocator usage.

        Returned info can be used to monitor memory usage per allocator.
        For example, the amount of internal fragmentation is equal to UsedBlockUsage /
        UsedMemoryUsage. Or the percent of recycled memory is equal to FreeMemoryUsage /
        (UsedMemoryUsage + FreeMemoryUsage) * 100%.

        */
        RESOURCE_ALLOCATOR_INFO GetInfo() const override;

        /** \brief  Identifies the allocator type.

        The type is used for profiling and debugging purposes only.
        */
        const char* GetTypename() const override;

      private:
        friend BufferAllocator;
        friend ResourceAllocation;

        HRESULT CreateResourceInternal(const ALLOCATION_DESC& allocationDescriptor,
                                       const D3D12_RESOURCE_DESC& resourceDescriptor,
                                       D3D12_RESOURCE_STATES initialResourceState,
                                       const D3D12_CLEAR_VALUE* clearValue,
                                       ResourceAllocation** resourceAllocationOut);

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

        static HRESULT ReportLiveDeviceObjects(ComPtr<ID3D12Device> device);

        // MemoryAllocator interface
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        ComPtr<ID3D12Device> mDevice;
        ComPtr<ResidencyManager> mResidencyManager;

        std::unique_ptr<Caps> mCaps;

        const bool mIsUMA;
        const D3D12_RESOURCE_HEAP_TIER mResourceHeapTier;
        const bool mIsAlwaysCommitted;
        const bool mIsAlwaysInBudget;
        const uint64_t mMaxResourceHeapSize;
        const bool mShutdownEventTrace;

        static constexpr uint64_t kNumOfResourceHeapTypes = 8u;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceHeapAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mBufferAllocatorOfType;

        std::unique_ptr<DebugResourceAllocator> mDebugAllocator;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
