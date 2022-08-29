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

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/d3d12/EventRecordD3D12.h"
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "include/gpgmm_export.h"

#include <array>
#include <memory>
#include <string>

namespace gpgmm {
    class MemoryAllocator;
}  // namespace gpgmm

namespace gpgmm::d3d12 {

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

        /** \brief Disable re-use of resource heap.

        A committed resource is allocated through D3D12 instead of GPGMM. This could be favorable
        for large static resources. Otherwise, this is mostly used for debugging and testing
        purposes.
        */
        ALLOCATOR_FLAG_ALWAYS_COMMITED = 0x1,

        /** \brief Creates resource within budget.

        By default (and when residency is used), resources will not be created resident unless an
        operation is performed on the allocation that requires them to be (ex. Map). Otherwise, the
        resource will become resident once ExecuteCommandList() is called. However, this flag can be
        used to change this behavior by requiring resource heaps to be always resident at resource
        creation. When residency is not used, ALLOCATOR_FLAG_ALWAYS_IN_BUDGET is implicitly enabled
        through the GPU/driver instead of explicitly through GPGMM.
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
    };

    DEFINE_ENUM_FLAG_OPERATORS(ALLOCATOR_FLAGS)

    /** \enum ALLOCATOR_ALGORITHM
    Specify the algorithms used for allocation.
    */
    enum ALLOCATOR_ALGORITHM {
        /** \brief Use default allocation mechanism.
         */
        ALLOCATOR_ALGORITHM_DEFAULT = 0,

        /** \brief Use the slab allocation mechanism.

        Slab allocation allocates/deallocates in O(1) time using O(N * pageSize) space.

        Slab allocation does not suffer from internal fragmentation but could externally fragment
        when many unique request sizes are used.
        */
        ALLOCATOR_ALGORITHM_SLAB = 1,

        /** \brief Use the buddy system mechanism.

        Buddy system allocate/deallocates in O(Log2) time using O(1) space.

        Buddy system suffers from internal fragmentation (ie. resources are not a power-of-two) but
        does not suffer from external fragmentation as much since the resource heap size does not
        change.

        It is recommend to specify a PreferredResourceHeapSize large enough such that multiple
        requests can fit within the specified PreferredResourceHeapSize but not too large where
        creating the larger resource heap becomes a bigger bottleneck.
        */
        ALLOCATOR_ALGORITHM_BUDDY_SYSTEM = 2,

        /** \brief Recycles resource heaps of a size being specified.

        Fixed pools allocate/deallocate in O(1) time using O(N) space.

        Fixed-size pool limits recycling to resource heaps equal to
        PreferredResourceHeapSize. A PreferredResourceHeapSize of zero is effectively
        equivelent to ALLOCATOR_FLAG_ALWAYS_ON_DEMAND.
        */
        ALLOCATOR_ALGORITHM_FIXED_POOL = 3,

        /** \brief Recycles resource heaps of any size using multiple pools.

        Segmented pool allocate/deallocates in O(Log2) time using O(N * K) space.
        */
        ALLOCATOR_ALGORITHM_SEGMENTED_POOL = 4,
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
        ALLOCATOR_FLAGS Flags;

        /** \brief Minimum severity level to log messages to console.

        Messages with lower severity will be ignored.
        */
        D3D12_MESSAGE_SEVERITY MinLogLevel;

        /** \brief Specifies recording options.

        For example, what events to record, and where to record them.
        */
        EVENT_RECORD_OPTIONS RecordOptions;

        /** \brief Specifies the adapter's tier of resource heap support.

        Used to determine if resource categories (texture and buffers) can co-exist in the
        same resource heap.

        Required parameter. Use CheckFeatureSupport to get supported tier.
        */
        D3D12_RESOURCE_HEAP_TIER ResourceHeapTier;

        /** \brief Specifies the algorithm to use for sub-allocation.

        Used to evaluate how allocation implementations perform with various algorithms that
        sub-divide resource heaps.

        Optional parameter. By default, the slab allocator is used.
        */
        ALLOCATOR_ALGORITHM SubAllocationAlgorithm;

        /** \brief Specifies the algorithm to use for resource heap pooling.

        Used to evaluate how allocation implementations perform with various algorithms that
        sub-divide resource heaps.

        Optional parameter. By default, the slab allocator is used.
        */
        ALLOCATOR_ALGORITHM PoolAlgorithm;

        /** \brief Specifies the preferred size of the resource heap.

        The preferred size of the resource heap is the minimum heap size to sub-allocate from.
        A larger resource heap consumes more memory but could be faster for sub-allocation.

        Optional parameter. When 0 is specified, the API will automatically set the preferred
        resource heap size to be a multiple of minimum resource heap size allowed by D3D12.
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

        /** \brief Memory fragmentation limit, expressed as a percentage of the resource heap size,
        that is acceptable to be wasted due to fragmentation.

        Fragmentation occurs when the allocation is larger then the resource size.
        This occurs when the type of resource (buffer or texture) and allocator have different
        alignment requirements. For example, a 192KB resource may need to allocate 256KB of
        allocated space, which is equivalent to a fragmentation limit of 33%.

        When PreferredResourceHeapSize is non-zero, the MemoryFragmentationLimit could be
        exceeded. Also, the MemoryFragmentationLimit should never be zero, as some fragmentation
        can occur.

        Optional parameter. When 0 is specified, the default fragmentation limit is 1/8th the
        resource heap size.
        */
        double MemoryFragmentationLimit;

        /** \brief Memory growth factor, expressed as a multipler of the resource heap size
        that will monotonically increase.

        A factor value of 1.0 specifies no growth, where the resource heap size is always determined
        by other limits or constraints. If no factor gets specified (or a value less than 1 is
        specified), GPGMM will allocate a resource heap size with enough space to fit exactly one
        resource.

        Memory growth avoids the need to specify |PreferredResourceHeapSize|, which
        especially helps in situations where the resource size cannot be predicated (eg.
        user-defined), by allowing the resource heap size to gradually increase in size
        per demand to achieve a balance of memory usage and performance.

        Optional parameter. When 0 is specified, the default of 1.25 is used (or 25% growth).
        */
        double MemoryGrowthFactor;
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
        allocating for contiguous allocations or many resources of the same size.

        Should not be used with ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY.
        */
        ALLOCATION_FLAG_ALWAYS_PREFETCH_MEMORY = 0x8,

        /** \brief Cache the request size.

        Allow internal data structures used for resource allocation to be cached in-memory.
        */
        ALLOCATION_FLAG_ALWAYS_CACHE_SIZE = 0x10,
    };

    DEFINE_ENUM_FLAG_OPERATORS(ALLOCATION_FLAGS)

    /** \struct ALLOCATION_FLAGS
    Specifies how allocations should be created.
    */
    struct ALLOCATION_DESC {
        /** \brief Flags used to control how the resource will be allocated.

        Optional parameter. By default, GPGMM will decide automatically.
        */
        ALLOCATION_FLAGS Flags;

        /** \brief Heap type that the resource to be allocated requires.

        Required parameter.
        */
        D3D12_HEAP_TYPE HeapType;

        /** \brief Additional heap flags that the resource requires.

        By default, GPGMM infers the required heap flags based on the required
        fields in the D3D12_RESOURCE_DESC, ALLOCATOR_DESC and ALLOCATION_DESC.
        But if additional heap flags are required, they can also be specified.

        It is recommended to only specify D3D12_HEAP_FLAG_NONE since not all
        allocation methods are guarenteed to be supported.

        Optional parameter.
        */
        D3D12_HEAP_FLAGS ExtraRequiredHeapFlags;

        /** \brief Require additional bytes to be appended to the resource allocation.

        Resource heap size is guarenteed to increase by at-least this number of bytes.
        Specifying a padding will disable committed resources and sub-allocated
        heaps.

        Used to workaround driver bugs related to the heap size being insufficent for the resource.

        Optional parameter. No extra padding is applied by default.
        */
        uint64_t RequireResourceHeapPadding;

        /** \brief Associates a name with the given allocation.

        Optional parameter. By default, no name is associated.
        */
        std::string DebugName;
    };

    /** \struct FEATURE_DATA_RESOURCE_SUBALLOCATION_SUPPORT

    Details the resource allocator limitations, including if sharing resources between command
    queues is coherent.
    */
    struct FEATURE_DATA_RESOURCE_SUBALLOCATION_SUPPORT {
        /** \brief Describes multi-queue resource access behavior.

        For example, if two allocations belong to the same resource where each allocation is
        referenced with a different command-queue, will accessing one stomp over the other. D3D12
        does not guarentee such behavior is safe but is it well-defined behavior based on the GPU
        vendor.
        */
        bool IsResourceAccessAlwaysCoherent;
    };

    /** \enum FEATURE

    Defines constants that specify a resource allocator feature to query about. When you
    want to query for the level to which an allocator supports a feature, pass one of these values
    to ResourceAllocator::CheckFeatureSupport.
    */
    enum FEATURE {
        /** \brief Indicates a query for the level of support for sub-allocated resources. The
        corresponding data structure for this value is FEATURE_DATA_RESOURCE_SUBALLOCATION_SUPPORT
        */
        FEATURE_RESOURCE_SUBALLOCATION_SUPPORT,
    };

    using RESOURCE_ALLOCATOR_INFO = MemoryAllocatorInfo;

    /** \brief ResourceAllocator is a MemoryAllocator that creates ID3D12Resources in a
    ResourceAllocation.

    Internally, ResourceAllocator creates a request, by determining the
    resource allocation requirements, then finds a MemoryAllocator able to service the request.

    If the first MemoryAllocator attempt fails, it will try a second MemoryAllocator, and so on.
    MemoryAllocator attempts are greedy: re-use of resources > re-use of heaps >
    re-use by pools > no re-use, in order of maximizing performance while minimizing memory
    footprint.

    ResourceAllocator also uses ResidencyManager to determine available memory
    (or budget left) when creating the request. This is because residency is managed
    per heap and not per resource). A larger Heap could be ideal for allocation but only if there is
    budget. And similarly, a smaller Heap allows for finer grained residency but could increase
    overall memory usage for allocation.
    **/
    class GPGMM_EXPORT ResourceAllocator final : public MemoryAllocator, public IUnknownImpl {
      public:
        /** \brief Create allocator with residency.

        Residency requires at-least DXGI version 1.4.

        @param allocatorDescriptor A reference to ALLOCATOR_DESC structure that describes the
        allocator.
        @param[out] ppResourceAllocatorOut Pointer to a memory block that recieves a pointer to the
        resource allocator. Pass NULL to test if allocator creation would succeed, but not actually
        create the allocator.
        @param[out] ppResidencyManagerOut Pointer to a memory block that recieves a pointer to the
        residency manager. If NULL is passed, the allocator will be created without using
        residency.
        */
        static HRESULT CreateAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                       ResourceAllocator** ppResourceAllocatorOut,
                                       ResidencyManager** ppResidencyManagerOut = nullptr);

        /** \brief Create allocator using a specified residency manager.

        @param allocatorDescriptor A reference to ALLOCATOR_DESC structure that describes the
        allocator.
        @param pResidencyManager Pointer to a memory block that recieves a pointer to the
        residency manager.
        @param[out] ppResourceAllocatorOut Pointer to a memory block that recieves a pointer to the
        resource allocator. Pass NULL to test if allocator creation would succeed, but not actually
        create the allocator.
        */
        static HRESULT CreateAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                       ResidencyManager* pResidencyManager,
                                       ResourceAllocator** ppResourceAllocatorOut);

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
        @param pClearValue A pointer tp D3D12_CLEAR_VALUE structure that describes the default value
        for a clear color.
        @param[out] ppResourceAllocationOut An optional pointer to a memory block that recieves the
        required interface pointer to the created resource allocation object.
        */
        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialResourceState,
                               const D3D12_CLEAR_VALUE* pClearValue,
                               ResourceAllocation** ppResourceAllocationOut);

        /** \brief  Imports an existing D3D12 resource.

        Allows externally created D3D12 resources to be used as ResourceAllocations.

        Residency is not supported for imported resources.

        @param committedResource A COM managed pointer to a D3D12 committed resource.
        @param[out] ppResourceAllocationOut Pointer to a memory block that recieves a pointer to the
        resource allocation. Pass NULL to test if resource allocation creation would succeed, but
        not actually create the resource allocation. If NULL is passed and resource allocation
        creation would succeed, S_FALSE is returned.
        */
        HRESULT CreateResource(ComPtr<ID3D12Resource> committedResource,
                               ResourceAllocation** ppResourceAllocationOut);

        /** \brief Return free memory back to the OS.

        When pooling is enabled, the allocator will retain resource heaps in order to speed-up
        subsequent resource allocation requests. These resource allocations count against the
        app's memory usage and in general, will lead to increased memory usage by the overall
        system. Apps should call ReleaseMemory() when going idle for a period of time since there is
        a brief performance hit when the internal resource heaps get reallocated by the OS.

        @param bytesToRelease Amount of memory to release, in bytes. A kInvalidSize means ALL memory
        will be released.

        \return Amount of memory, in bytes, released. The released size might be smaller then
        bytesToRelease if there was not enough memory or larger if releasable memory doesn't exactly
        total up to the amount.
        */
        uint64_t ReleaseMemory(uint64_t bytesToRelease = kInvalidSize) override;

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

        /** \brief Gets information about the features that are supported by the resource allocator.

        @param feature A constant from the FEATURE enumeration describing the feature(s)
        that you want to query for support.
        @param pFeatureSupportData A pointer to the data structure that corresponds to the value of
        the feature parameter. To determine the corresponding data structure for each constant, see
        FEATURE.
        @param featureSupportDataSize The sie of the structure pointed by the pFeatureSupportData
        parameter.

        \return Returns S_OK if successful. Returns E_INVALIDARG if unsupported data type is passed
        to pFeatureSupportData or if a size mismatch is detected for the featureSupportDataSize
        parameter.
        */
        HRESULT CheckFeatureSupport(FEATURE feature,
                                    void* pFeatureSupportData,
                                    uint32_t featureSupportDataSize) const;

      private:
        friend BufferAllocator;
        friend ResourceAllocation;

        HRESULT CreateResourceInternal(const ALLOCATION_DESC& allocationDescriptor,
                                       const D3D12_RESOURCE_DESC& resourceDescriptor,
                                       D3D12_RESOURCE_STATES initialResourceState,
                                       const D3D12_CLEAR_VALUE* clearValue,
                                       ResourceAllocation** ppResourceAllocationOut);

        ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                          ComPtr<ResidencyManager> residencyManager,
                          std::unique_ptr<Caps> caps);

        std::unique_ptr<MemoryAllocator> CreateResourceSubAllocator(
            const ALLOCATOR_DESC& descriptor,
            D3D12_HEAP_FLAGS heapFlags,
            D3D12_HEAP_TYPE heapType,
            uint64_t heapAlignment);

        std::unique_ptr<MemoryAllocator> CreateResourceHeapAllocator(
            const ALLOCATOR_DESC& descriptor,
            D3D12_HEAP_FLAGS heapFlags,
            D3D12_HEAP_TYPE heapType,
            uint64_t heapAlignment);

        std::unique_ptr<MemoryAllocator> CreateSmallBufferAllocator(
            const ALLOCATOR_DESC& descriptor,
            D3D12_HEAP_FLAGS heapFlags,
            D3D12_HEAP_TYPE heapType,
            uint64_t heapAlignment);

        HRESULT CreatePlacedResource(Heap* const resourceHeap,
                                     uint64_t resourceOffset,
                                     const D3D12_RESOURCE_DESC* resourceDescriptor,
                                     const D3D12_CLEAR_VALUE* clearValue,
                                     D3D12_RESOURCE_STATES initialResourceState,
                                     ID3D12Resource** placedResourceOut);

        HRESULT CreateCommittedResource(D3D12_HEAP_TYPE heapType,
                                        D3D12_HEAP_FLAGS heapFlags,
                                        const D3D12_RESOURCE_ALLOCATION_INFO& info,
                                        const D3D12_RESOURCE_DESC* resourceDescriptor,
                                        const D3D12_CLEAR_VALUE* clearValue,
                                        D3D12_RESOURCE_STATES initialResourceState,
                                        ID3D12Resource** commitedResourceOut,
                                        Heap** resourceHeapOut);

        static HRESULT ReportLiveDeviceObjects(ComPtr<ID3D12Device> device);

        bool IsCreateHeapNotResident() const;

        // MemoryAllocator interface
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        RESOURCE_ALLOCATOR_INFO GetInfoInternal() const;

        ComPtr<ID3D12Device> mDevice;
        ComPtr<ResidencyManager> mResidencyManager;

        std::unique_ptr<Caps> mCaps;

        const D3D12_RESOURCE_HEAP_TIER mResourceHeapTier;
        const bool mIsAlwaysCommitted;
        const bool mIsAlwaysInBudget;
        const bool mFlushEventBuffersOnDestruct;
        const bool mUseDetailedTimingEvents;

        static constexpr uint64_t kNumOfResourceHeapTypes = 8u;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceHeapAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceAllocatorOfType;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mMSAAResourceHeapAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mMSAAResourceAllocatorOfType;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mSmallBufferAllocatorOfType;

        std::unique_ptr<DebugResourceAllocator> mDebugAllocator;
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
