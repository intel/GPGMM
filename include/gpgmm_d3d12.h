// Copyright 2022 The GPGMM Authors
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

#ifndef INCLUDE_GPGMM_D3D12_H_
#define INCLUDE_GPGMM_D3D12_H_

// gpgmm_d3d12.h is the GMM interface implemented by GPGMM for D3D12.
// This file should not be modified by downstream GMM clients or forks of GPGMM.
// Please consider submitting a pull-request to https://github.com/intel/gpgmm.

// User should decide to define the following macros:
// - GPGMM_SHARED_LIBRARY: the implementation using this header wishes to be built as a shared
// library.
// - GPGMM_D3D12_HEADERS_ALREADY_INCLUDED: D3D12 platform headers will be already included before
// this header and does not need to be re-included.
// - GPGMM_WINDOWS_HEADERS_ALREADY_INCLUDED: Windows.h will be already included before this header
// and does not need to be re-included.

#ifdef GPGMM_SHARED_LIBRARY
#    include "gpgmm_export.h"
#else  // defined(GPGMM_SHARED_LIBRARY)
#    define GPGMM_EXPORT
#endif  // defined(GPGMM_SHARED_LIBRARY)

#ifndef GPGMM_D3D12_HEADERS_ALREADY_INCLUDED
#    include <d3d12.h>
#    include <dxgi1_4.h>
#endif  // defined(GPGMM_D3D12_HEADERS_ALREADY_INCLUDED)

#ifndef GPGMM_WINDOWS_HEADERS_ALREADY_INCLUDED
#    include <windows.h>  // for DEFINE_ENUM_FLAG_OPERATORS
#endif                    // defined(GPGMM_WINDOWS_HEADERS_ALREADY_INCLUDED)

#define GPGMM_INTERFACE struct

namespace gpgmm::d3d12 {

    /** \brief Debug object associates additional information for D3D objects using SetPrivateData.

    Since a single D3D object could be re-used by one or more GPGMM objects, debug information must
    be stored and retrieved separately.
    */
    GPGMM_INTERFACE IDebugObject : public IUnknown {
        /** \brief Get the debug name.

        \return A NULL-terminated UNICODE string that contains the name to associate with the debug
        object.
        */
        virtual LPCWSTR GetDebugName() const = 0;

        /** \brief Associate a debug name.

        @param Name A NULL-terminated UNICODE string that contains the name to associate with the
        debug object.
        */
        virtual HRESULT SetDebugName(LPCWSTR Name) = 0;
    };

    /** \enum RESIDENCY_HEAP_STATUS

       D3D12 allows heaps to be explicitly created resident or not. This means the expected
       residency status of the heap cannot be solely determined by checking for the existence in a
       residency cache.

       Heaps are in one of three exclusive states: never made resident or unknown, about to become
       resident or pending residency, and currently resident. When a heap gets evicted or paged-out,
       it transitions from currently resident to pending residency. Paged-in is the reverse of this,
       pending residency to currently resident. If the heap was known to be created resident by
       D3D12, it will immediately become currently resident. If the heap becomes locked, it will
       stay currently resident until it is evicted, then back to pending residency.
    */
    enum RESIDENCY_HEAP_STATUS {
        /** \brief Heap residency status is not known and cannot be made resident.
         Heap must become locked to be managed for residency.
         */
        RESIDENCY_HEAP_STATUS_UNKNOWN = 0,

        /** \brief Heap is about to be made resident.
        Heap must be previously locked, evicted, or currently resident at creation.
        */
        RESIDENCY_HEAP_STATUS_PENDING = 1,

        /** \brief Heap was made resident and can be evicted.
        Heaps that stay locked will always be currently resident.
        */
        RESIDENCY_HEAP_STATUS_CURRENT = 2,
    };

    /** \struct RESIDENCY_HEAP_INFO
    Additional information about the heap.
    */
    struct RESIDENCY_HEAP_INFO {
        /** \brief Created size, in bytes, of the heap.

        Must be non-zero. SizeInBytes is always a multiple of the alignment.
        */
        UINT64 SizeInBytes;

        /** \brief Created alignment, in bytes, of the heap.

        Must be non-zero.
        */
        UINT64 Alignment;

        /** \brief Check if the heap is currently locked for residency.

        A locked heap means the heap is not eligible for eviction.
        */
        bool IsLocked;

        /** \brief Check if the heap was made resident or not.
         */
        RESIDENCY_HEAP_STATUS Status;
    };

    /** \enum RESIDENCY_HEAP_FLAGS
    Specify creation options to configure the heap.
    */
    enum RESIDENCY_HEAP_FLAGS {

        /** \brief Disables all option flags.
         */
        RESIDENCY_HEAP_FLAG_NONE = 0x0,

        /** \brief Requires the heap to be created in budget.

        This flags ensures there is enough budget to exist for the heap or E_OUTOFMEMORY.
        */
        RESIDENCY_HEAP_FLAG_ALWAYS_IN_BUDGET = 0x1,

        /** \brief Requires the heap to be tracked for residency.

        This flag is equivalent to calling LockHeap then UnlockHeap after
        creation. The flag only has effect when the heap's residency status
        cannot be determined.
        */
        RESIDENCY_HEAP_FLAG_ALWAYS_RESIDENT = 0x2,
    };

    DEFINE_ENUM_FLAG_OPERATORS(RESIDENCY_HEAP_FLAGS)

    /** \struct RESIDENCY_HEAP_DESC
      Specifies creation options for a residency managed heap.
      */
    struct RESIDENCY_HEAP_DESC {
        /** \brief Created size of the heap, in bytes.

        Must be non-zero. SizeInBytes is always a multiple of the alignment.
        */
        UINT64 SizeInBytes;

        /** \brief Created alignment of the heap, in bytes.

        Must be non-zero.
        */
        UINT64 Alignment;

        /** \brief Specifies the memory segment the heap will reside in.

        Required parameter.
        */
        DXGI_MEMORY_SEGMENT_GROUP HeapSegment;

        /** \brief Specifies heaps options.

        Optional parameter. By default, no flags are specified or RESIDENCY_HEAP_FLAG_NONE.
        */
        RESIDENCY_HEAP_FLAGS Flags;

        /** \brief Debug name associated with the heap.

        Optional parameter. By default, no name is associated.
        */
        LPCWSTR DebugName;
    };

    /** \brief Callback function used to create a ID3D12Pageable.
     */
    using CreateHeapFn = HRESULT (*)(void* pCreateHeapContext, ID3D12Pageable** ppPageableOut);

    GPGMM_INTERFACE IResidencyManager;

    /** \brief Heap represents a residency-managed ID3D12Pageable object.

    For example, a Heap could represent a "resource heap" (ID3D12Heap or committed ID3D12Resource)
    or ID3D12DescriptorHeap and so on.

    Heap serves as a node within the ResidencyManager's residency cache. This node is inserted into
    the cache when it is first created, and any time it is scheduled to be used by the GPU. This
    node is removed from the cache when it is evicted from video memory due to budget constraints,
    or when the memory is released.
    */
    GPGMM_INTERFACE IResidencyHeap : public IDebugObject {
        /** \brief Returns information about this heap.

        \return A RESIDENCY_HEAP_INFO struct containing the information.
        */
        virtual RESIDENCY_HEAP_INFO GetInfo() const = 0;
    };

    /** \brief  Create a heap managed by GPGMM.

    Unlike a normal D3D12 heap, a heap managed by GPGMM means it will be tracked for residency
    purposes. A heap managed by GPGMM represents either a 1) committed resource backed by
    implicit D3D12 heap OR 2) an explicit D3D12 heap used with placed resources.

    @param descriptor A reference to RESIDENCY_HEAP_DESC structure that describes the heap.
    @param pResidencyManager A pointer to the ResidencyManager used to manage this heap.
    @param createHeapFn  A callback function which creates a ID3D12Pageable derived type.
    @param pCreateHeapContext  A pointer to a class designed to implement the actual heap creation
    function and store any necessary variables.
    @param[out] ppResidencyHeapOut Pointer to a memory block that receives a pointer to the
    heap.

    Example call showing the usage of createHeapFn and pCreateHeapContext:

    \code
    CreateResidencyHeap(descriptor, pResidencyManager, CallbackContext:CallbackWrapper,
    reinterpret_cast<void*>(callbackContext), ppResidencyHeapOut);
    \endcode

    Example Callback Context Class:

    \code
    class CallbackContext {
        public:
            CallbackContext(<Pass variables needed for heap creation here>);
            CreateResidencyHeap(void *context, ID3D12Pageable** ppPageableOut);
            static CallbackWrapper(ID3D12Pageable** ppPageableOut);
        private:
            (Declare variables needed for heap creation here)
    }
    \endcode

    Example implementation of CallbackWrapper:

    \code
    HRESULT CallbackContext:CallbackWrapper(void* context, ID3D12Pageable** ppPageableOut) {
        CallbackContext* callbackContext = reinterpret_cast<CallbackContext*>(context);
        return callbackContext->CreateResidencyHeap(ppPageableOut);
    }
    \endcode
    */
    GPGMM_EXPORT HRESULT CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                             IResidencyManager* const pResidencyManager,
                                             CreateHeapFn createHeapFn,
                                             void* pCreateHeapContext,
                                             IResidencyHeap** ppResidencyHeapOut);

    /** \brief  Create a heap managed by GPGMM.

    This version of CreateResidencyHeap is a simpler way to create residency heaps by disallowing
    use of RESIDENCY_HEAP_FLAG_ALWAYS_IN_BUDGET by specifying the pageable instead.

    @param descriptor A reference to RESIDENCY_HEAP_DESC structure that describes the heap.
    @param pResidencyManager A pointer to the ResidencyManager used to manage this heap.
    @param pPageable  A pointer to the pageable object that represents the heap.
    @param[out] ppResidencyHeapOut Pointer to a memory block that receives a pointer to the
    heap.
    */
    GPGMM_EXPORT HRESULT CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                             IResidencyManager* const pResidencyManager,
                                             ID3D12Pageable* pPageable,
                                             IResidencyHeap** ppResidencyHeapOut);

    /** \brief Represents a list of heaps which will be "made resident" upon executing a
    command-list.

    A residency list helps track heaps for residency which will be referenced together by a
    command-list. The application uses a ResidencyList by inserting heaps, by calling
    ResourceAllocation::GetMemory, into the list. Once ResidencyManager::ExecuteCommandLists is
    called, the list can be reset or cleared for the next frame or compute job.

    Without ResidencyList, the application would need to call ResidencyManager::LockHeap and
    ResidencyManager::UnlockHeap for each heap before and after every GPU command or command-list
    being executed.
    */
    GPGMM_INTERFACE IResidencyList : public IUnknown {
        /** \brief  Adds a heap to the residency list.

        @param pHeap A pointer to Heap about to be added.

        \return Returns S_OK if successful.
        */
        virtual HRESULT Add(IResidencyHeap * pHeap) = 0;

        /** \brief Resets a residency list to its initial state as if a new residenct list was
        created.

        \return Returns S_OK if successful.
        */
        virtual HRESULT Reset() = 0;
    };

    /** \enum RECORD_FLAGS
      Represents different event categories to record.
      */
    enum RECORD_FLAGS {

        /** \brief Record nothing.
         */
        RECORD_FLAGS_NONE = 0x0,

        /** \brief Record lifetimes of API objects created by GPGMM.
         */
        RECORD_FLAGS_API_OBJECTS = 0x1,

        /** \brief Record API calls made to GPGMM.
         */
        RECORD_FLAGS_API_CALLS = 0x2,

        /** \brief Record duration of GPGMM API calls.
         */
        RECORD_FLAGS_API_TIMINGS = 0x4,

        /** \brief Record metrics made to GPGMM API calls.
         */
        RECORD_FLAGS_COUNTERS = 0x8,

        /** \brief Record events required for playback.

         Bitwise OR'd combination of kApiObjects and
         kApiCalls.
         */
        RECORD_FLAGS_CAPTURE = 0x3,

        /** \brief Record everything.
         */
        RECORD_FLAGS_ALL = 0xFF,
    };

    DEFINE_ENUM_FLAG_OPERATORS(RECORD_FLAGS)

    /** \enum RECORD_SCOPE
    Represents recording scopes to limit event recording.
    */
    enum RECORD_SCOPE {

        /** \brief Scopes events per process (or multiple instances).
         */
        RECORD_SCOPE_PER_PROCESS = 0,

        /** \brief Scopes events per instance.
         */
        RECORD_SCOPE_PER_INSTANCE = 1,
    };

    /** \struct RECORD_OPTIONS
    Represents additional controls for recording.
    */
    struct RECORD_OPTIONS {
        /** \brief Flags used to decide what to record.

        Optional parameter. By default, nothing is recorded.
        */
        RECORD_FLAGS Flags;

        /** \brief Specifies the scope of the events.

        Optional parameter. By default, recording is per process.
        */
        RECORD_SCOPE EventScope;

        /** \brief Record detailed timing events.

        Optional parameter. By default, detailed timing events are disabled.
        */
        bool UseDetailedTimingEvents;

        /** \brief Path to trace file.

        Optional parameter. By default, a trace file is created for you.
        */
        const char* TraceFile;
    };

    /** \brief  Create a residency list or collection of heaps to manage together for residency.

    @param[out] ppResidencyListOut An optional pointer to a memory block that receives the
    required interface pointer to the created residency list object.

    \return Returns S_OK if successful.
     */
    GPGMM_EXPORT HRESULT CreateResidencyList(IResidencyList** ppResidencyListOut);

    /** \enum RESIDENCY_MANAGER_FLAGS
       Specify options to configure the residency manager.
       */
    enum RESIDENCY_MANAGER_FLAGS {

        /** \brief Disables all option flags.
         */
        RESIDENCY_FLAG_NONE = 0x0,

        /** \brief Allow background budget updates from OS notifications.

        By default, budget updates will be queried by the residency manager
        instead of pushed by OS notifications using a background thread.
        */
        RESIDENCY_FLAG_ALLOW_BACKGROUND_BUDGET_UPDATES = 0x1,

        /** \brief Specifies if unified memory architecture (UMA) is always disabled.

        By default, UMA is enabled when the adapter supports the architecture.
        UMA allows the residency manager to budget using a single memory segment.
        Otherwise, the residency manager will have two budgets for local and non-local
        memory segments, respectively.
        */
        RESIDENCY_FLAG_DISABLE_UNIFIED_MEMORY = 0x2,

        /** \brief Requires heaps to be in budget or E_OUTOFMEMORY.

        With this flag, heaps created for this residency manager will effectively never
        specify D3D12_RESIDENCY_FLAG_DENY_OVERBUDGET.
        */
        RESIDENCY_FLAG_ALWAYS_IN_BUDGET = 0x4,
    };

    DEFINE_ENUM_FLAG_OPERATORS(RESIDENCY_MANAGER_FLAGS)

    /** \struct RESIDENCY_MANAGER_DESC
     Specify parameters when creating a residency manager.
     */
    struct RESIDENCY_MANAGER_DESC {
        /** \brief Specifies residency options.

        Optional parameter. By default, no flags are specified or RESIDENCY_FLAG_NONE.
        */
        RESIDENCY_MANAGER_FLAGS Flags;

        /** \brief Minimum severity level to record messages.

        Messages with lower severity will be ignored.

        Optional parameter. By default, the minimum severity level is WARN.
        */
        D3D12_MESSAGE_SEVERITY MinRecordLevel;

        /** \brief Minimum severity level to log messages to console.

        Messages with lower severity will be ignored.

        Optional parameter. By default, will log only corruption messages.
        */
        D3D12_MESSAGE_SEVERITY MinLogLevel;

        /** \brief Specifies recording options.

        For example, what events to record, and where to record them.

        Optional parameter. By default, no options are specified for recording.
        */
        RECORD_OPTIONS RecordOptions;

        /** \brief Maximum amount of budgeted memory, expressed as a percentage of video memory,
        that can be budgeted.

        If a non-zero MaxBudgetInBytes is specified, MaxPctOfVideoMemoryToBudget is ignored.

        Optional parameter. By default, the API will automatically set the budget to 95% of video
        memory, leaving 5% for the OS and other applications.
        */
        FLOAT MaxPctOfVideoMemoryToBudget;

        /** \brief Lowest amount of budgeted memory, expressed as a percentage, that can be
        reserved.

        If SetVideoMemoryReservation is used a set a reservation larger then the budget, this amount
        is used instead so the application can make forward progress.

        Optional parameter. By default, the API restricts the residency manager reservation to never
        go below 50% of the budget.
        */
        FLOAT MinPctOfBudgetToReserve;

        /** \brief Maximum amount of budgeted memory, in bytes, that can be budgeted.

        Allows a fixed budget to be artificially set for testing purposes.

        Optional parameter. By default, the API will not further restrict the residency manager
        budget.
        */
        UINT64 MaxBudgetInBytes;

        /** \brief Size of memory, in bytes, to evict from residency at once,
        should there not be enough budget left.

        Optional parameter. When 0 is specified, the API will use a evict size of 50MB.
        */
        UINT64 EvictSizeInBytes;

        /** \brief Initial fence value to use when managing heaps for residency.

        Fence value gets assigned to each managed heap and increments each time ExecuteCommandList()
        is called. When over budget, these fence values are compared to determine which heaps can be
        evicted.

        Optional parameter. Zero by default.
        */
        UINT64 InitialFenceValue;
    };

    /** \struct RESIDENCY_MANAGER_STATS
    Additional information about residency manager usage.
    */
    struct RESIDENCY_MANAGER_STATS {
        /** \brief Amount of memory, in bytes, currently resident.
         */
        UINT64 CurrentHeapUsage;

        /** \brief Number of heaps, currently resident.
         */
        UINT64 CurrentHeapCount;
    };

    /** \enum ALLOCATION_TYPE
    Represents how memory was allocated.
    */
    enum ALLOCATION_TYPE {
        /** \brief Not yet allocated or invalid.

        This is an invalid state that assigned temporary before the actual method is known.
        */
        ALLOCATION_TYPE_UNKNOWN = 0,

        /** \brief Not sub-divided.

        One and only one allocation exists for the memory.
        */
        ALLOCATION_TYPE_STANDALONE = 1,

        /** \brief Sub-divided using one or more allocations.

        Underlying memory will be broken up into one or more memory allocations.
        */
        ALLOCATION_TYPE_SUBALLOCATED = 2,

        /** \brief Sub-divided within a single memory allocation.

        A single memory allocation will be broken into one or more sub-allocations.
        */
        ALLOCATION_TYPE_SUBALLOCATED_WITHIN = 3,
    };

    /** \brief ResidencyManager tracks and maintains one or more Heap within a residency cache.

    A Heap is considered "resident" when it is accessible by the GPU. A Heap can be made explicitly
    resident by calling ResidencyManager::LockHeap or implicitly resident by using the Heap with a
    ResidencyList upon calling ResidencyManager::ExecuteCommandLists or through a
    operation that always requires the Heap to be resident (eg. Map, Unmap).

    Internally, the ResidencyManager keeps the application in-budget by calling ID3D12Device::Evict
    and ID3D12Device::MakeResident to page-out or page-in heaps, respectively.
    **/
    GPGMM_INTERFACE IResidencyManager : public IDebugObject {
      public:
        /** \brief Locks the specified heap.

        Locking a heap means the residency manager will never evict it when over budget.

        @param pHeap A pointer to the heap being locked.
        */
        virtual HRESULT LockHeap(IResidencyHeap * pHeap) = 0;

        /** \brief Unlocks the specified heap.

        Unlocking a heap allows the residency manager will evict it when over budget.

        @param pHeap A pointer to the heap being unlocked.
        */
        virtual HRESULT UnlockHeap(IResidencyHeap * pHeap) = 0;

        /** \brief Execute command lists using residency managed heaps or E_OUTOFMEMORY.

        Submits an array of command lists and residency lists for the specified command queue.
        Unlike calling ExecuteCommandLists directly, errors will be returned should memory be
        exhausted.

        @param pQueue The command queue to submit to. May be nullptr. When nullptr, only residency
        operations are performed.
        @param ppCommandLists The array of ID3D12CommandList command lists to be executed. May be
        nullptr. When nullptr, only residency operations are performed.
        @param ppResidencyLists The array of ResidencyList residency lists to make resident.
        @param count The size of commandLists and residencyLists arrays.
        */
        virtual HRESULT ExecuteCommandLists(
            ID3D12CommandQueue* const pQueue, ID3D12CommandList* const* ppCommandLists,
            IResidencyList* const* ppResidencyLists, UINT count) = 0;

        /** \brief Sets video memory reservation.

        A reservation is the lowest amount of physical memory the application need to continue
        operation safely.

        @param heapSegment Memory segment to reserve.
        @param availableForReservation Amount of memory to reserve, in bytes.
        @param[out] pCurrentReservationOut the amount of memory reserved, which may be less then the
        |reservation| when under video memory pressure. A value of nullptr will update but not
        return the current reservation.
        */
        virtual HRESULT SetVideoMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& heapSegment,
                                                  UINT64 availableForReservation,
                                                  UINT64* pCurrentReservationOut = nullptr) = 0;

        /** \brief Get the current budget and memory usage.

        @param heapSegment Memory segment to retrieve info from.
        @param[out] pVideoMemoryInfoOut Pointer to DXGI_QUERY_VIDEO_MEMORY_INFO to populate. A value
        of nullptr will update but not return the current info.
        */
        virtual HRESULT QueryVideoMemoryInfo(const DXGI_MEMORY_SEGMENT_GROUP& heapSegment,
                                             DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfoOut) = 0;

        /** \brief Update the residency status of a heap.

        Allows the application to explicitly MakeResident/Evict without using a residency manager
        operation. This is useful should the application already perform some residency management
        but also want to use a residency manager. It is the application developers responsibility to
        ensure MakeResident/Evict will be called before updating the residency status to
        CURRENT_RESIDENT/PENDING, respectively.

        @param pHeap A pointer to the heap being updated.
        @param state The RESIDENCY_HEAP_STATUS enum of the new status.
        */
        virtual HRESULT SetResidencyStatus(IResidencyHeap * pHeap,
                                           const RESIDENCY_HEAP_STATUS& state) = 0;

        /** \brief Query the current residency usage.

        @param pResidencyManagerStats A pointer to a RESIDENCY_MANAGER_STATS structure or NULL if
        statistics information should only be gathered for recording.

        \return Returns S_OK if successful. Returns S_FALSE if statistics information was only
        gathered for recording.
        */
        virtual HRESULT QueryStats(RESIDENCY_MANAGER_STATS * pResidencyManagerStats) = 0;
    };

    /** \brief  Create residency residency manager to manage video memory.

    @param descriptor A reference to RESIDENCY_MANAGER_DESC structure that describes the residency
    manager.
    @param pDevice device used by this allocator. Required parameter. Use CreateDevice get the
    device.
    @param pAdapter DXGI adapter used to create the device.  Requires DXGI 1.4 due to
    IDXGIAdapter3::QueryVideoMemoryInfo. Use EnumAdapters to get the adapter.
    @param[out] ppResidencyManagerOut Pointer to a memory block that receives a pointer to the
    residency manager. Pass NULL to test if residency Manager creation would succeed, but not
    actually create the residency Manager. If NULL is passed and residency manager creating
    would succeed, S_FALSE is returned.
    */
    GPGMM_EXPORT HRESULT CreateResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                                ID3D12Device* pDevice,
                                                IDXGIAdapter3* pAdapter,
                                                IResidencyManager** ppResidencyManagerOut);

    /** \struct RESOURCE_ALLOCATION_INFO
    Additional information about the resource allocation.
    */
    struct RESOURCE_ALLOCATION_INFO {
        /** \brief Created size, in bytes, of the resource allocation.

        Must be non-zero. SizeInBytes is always a multiple of the alignment.
        */
        UINT64 SizeInBytes;

        /** \brief Created alignment, in bytes, of the resource allocation.

        Must be non-zero.
        */
        UINT64 Alignment;

        /** \brief Describes the method used to allocate memory for the resource.
         */
        ALLOCATION_TYPE Type;
    };

    /** \brief ResourceAllocation is an allocation that contains a ID3D12Resource.

    It can represent a allocation using a resource in one of three ways: 1) ID3D12Resource "placed"
    in a ID3D12Heap, 2) a ID3D12Resource at a specific offset, or 3) a ID3D12Resource without a
    ID3D12Heap (called a committed resource).

    It is recommend to use ResourceAllocation instead of ID3D12Resource (1:1) for performing D3D12
    operations with it (eg. Map, Unmap, etc).
    */
    GPGMM_INTERFACE IResourceAllocation : public IDebugObject {
      public:
        /** \brief Maps the resource allocation.

        Gets the CPU pointer to the specified subresource of the resource allocation.

        If sub-allocated within the resource, the read or write range and
        pointer value will start from the allocation instead of the resource.

        @param subresource Specifies the index number of the subresource.
        @param pReadRange A pointer to a D3D12_RANGE structure that describes the range of memory to
        access.
        @param[out] ppDataOut A pointer to a memory block that receives a pointer to the resource
        data.
        */
        virtual HRESULT Map(UINT subresource, const D3D12_RANGE* pReadRange, void** ppDataOut) = 0;

        /** \brief Unmaps the resource allocation.

        Invalidates the CPU pointer to the specified subresource in the resource.

        @param subresource Specifies the index number of the subresource.
        @param pWrittenRange A pointer to a D3D12_RANGE structure that describes the range of memory
        to unmap.
        */
        virtual void Unmap(UINT subresource, const D3D12_RANGE* pWrittenRange) = 0;

        /** \brief Returns the resource owned by this allocation.

        \return Pointer to ID3D12Resource, owned by this allocation.
        */
        virtual ID3D12Resource* GetResource() const = 0;

        /** \brief Returns the GPU virtual address of the resource allocation.

        If sub-allocated within the resource, the GPU virtual address will
        start from the allocation instead of the resource.

        \return A D3D12_GPU_VIRTUAL_ADDRESS, equal to UINT64, to represent a location in GPU memory.
        */
        virtual D3D12_GPU_VIRTUAL_ADDRESS GetGPUVirtualAddress() const = 0;

        /** \brief Returns the start of the allocation in the resource.

        If sub-allocated within the resource, the offset could be greater than zero.

        \return A offset, in bytes, of the start of this allocation in the resource.
        */
        virtual UINT64 GetOffsetFromResource() const = 0;

        /** \brief Returns information about this resource allocation.

        \return A RESOURCE_ALLOCATION_INFO struct containing the information.
        */
        virtual RESOURCE_ALLOCATION_INFO GetInfo() const = 0;

        /** \brief Returns the heap assigned to this resource allocation.

        \return A pointer to the Heap used by this resource allocation.
        */
        virtual IResidencyHeap* GetMemory() const = 0;
    };

    /** \enum RESOURCE_ALLOCATOR_FLAGS
    Specify creation options for allocator.
    */
    enum RESOURCE_ALLOCATOR_FLAGS {

        /** \brief Disables all option flags.
         */
        ALLOCATOR_FLAG_NONE = 0x0,

        /** \brief Disable re-use of resource heap.

        A committed resource is allocated through D3D12 instead of GPGMM. This could be favorable
        for large static resources. Otherwise, this is mostly used for debugging and testing
        purposes.
        */
        RESOURCE_ALLOCATOR_FLAG_ALWAYS_COMMITTED = 0x1,

        /** \brief Requires resource allocation to be created within budget.

        Always use RESIDENCY_HEAP_FLAG_ALWAYS_IN_BUDGET to resource heaps created by this resource
        allocator.
        */
        RESOURCE_ALLOCATOR_FLAG_ALWAYS_IN_BUDGET = 0x2,

        /** \brief Allow pre-fetching of resource heaps on background thread.

        Allows GPGMM to trigger prefetching based on heurstics. Prefetching enables more
        performance when allocating for contiguous allocations or many resources of the same size.
        */
        RESOURCE_ALLOCATOR_FLAG_ALLOW_PREFETCH = 0x4,

        /** \brief Disables recycling of GPU memory.

        Forces the creation of new heaps and to de-allocate heaps immediately once no longer needed
        (instead of re-using it).

        This is very slow and not recommended for general use but may be useful for running with the
        minimal possible GPU memory footprint, avoiding out-of-memory, or debugging possible
        corruption of heaps.
        */
        RESOURCE_ALLOCATOR_FLAG_ALWAYS_ON_DEMAND = 0x8,

        /** \brief Uses D3D12_HEAP_TYPE_CUSTOM-equivalent upload heap everywhere on UMA.

        Allocates resources with a D3D12_HEAP_TYPE_CUSTOM-equivalent upload heap type from
        a single memory pool.
        */
        RESOURCE_ALLOCATOR_FLAG_ALLOW_UNIFIED_MEMORY = 0x10,

        /** \brief Report leaks of resource allocations.

        Used to track outstanding allocations made with this allocator. When the allocator is about
        to be released, it will report details on any leaked allocations as log messages.
        */
        RESOURCE_ALLOCATOR_FLAG_NEVER_LEAK = 0x20,

        /** \brief Requires resource allocation to be created resident.

        With this flag, resource heaps created by this resource allocator will never specify
        D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT, when supported, to avoid unnecessary GPU paging
        operations at resource creation, and instead, reverts back to the default behavior of D3D12
        of always making heaps implicitly resident on creation.
        */
        RESOURCE_ALLOCATOR_FLAG_ALWAYS_RESIDENT = 0x40,
    };

    DEFINE_ENUM_FLAG_OPERATORS(RESOURCE_ALLOCATOR_FLAGS)

    /** \enum ALLOCATOR_ALGORITHM
    Specify the algorithms used for allocation.
    */
    enum ALLOCATOR_ALGORITHM {
        /** \brief Use default allocation mechanism.

        Relies on internal heuristics to automatically determine the best allocation mechanism. The
        selection of algorithm depends on:

        1. The heap properties or flags specified by the user.
        2. The size the resource being created.
        3. The amount of available memory.

        In general, the most efficient resource allocator will be attempted first (efficient
        being defined as fastest service-time to allocate/deallocate with smallest memory
        footprint), subject to other constraints. However, since it's impossible to predict all
        future memory accesses, allocation techniques that rely on amortization of GPU heaps may not
        prove to be faster as expected. Further experimentation is recommended.
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
        equivalent to RESOURCE_ALLOCATOR_FLAG_ALWAYS_ON_DEMAND.
        */
        ALLOCATOR_ALGORITHM_FIXED_POOL = 3,

        /** \brief Recycles resource heaps of any size using multiple pools.

        Segmented pool allocate/deallocates in O(Log2) time using O(N * K) space.
        */
        ALLOCATOR_ALGORITHM_SEGMENTED_POOL = 4,

        /** \brief Use the dedicated allocation mechanism.

        Allows resources to be created as a dedicated allocation, rather than sub-allocated.

        A dedicated allocation allocates exactly what is needed for the resource and nothing more.

        Internally, dedicated allocations are "placed resources" which allows the heap to be
        recycled by GPGMM. Otherwise, RESOURCE_ALLOCATOR_FLAG_ALWAYS_COMMITTED is equivalent to a
        "dedicated allocation" but without heaps being recycled by GPGMM.

        Dedicated allocation allocates/deallocates in O(1) time using O(N * pageSize) space.
        */
        ALLOCATOR_ALGORITHM_DEDICATED = 5,
    };

    /** \struct RESOURCE_ALLOCATOR_DESC
    Specify parameters for creating allocators.
    */
    struct RESOURCE_ALLOCATOR_DESC {
        /** \brief Specifies allocator options.

        For example, whether the allocator can reuse memory, or resources should be resident upon
        creation.
        */
        RESOURCE_ALLOCATOR_FLAGS Flags;

        /** \brief Minimum severity level to record messages.

        Messages with lower severity will be ignored.

        Optional parameter. By default, the minimum severity level is WARN.
        */
        D3D12_MESSAGE_SEVERITY MinRecordLevel;

        /** \brief Minimum severity level to log messages to console.

        Messages with lower severity will be ignored.
        */
        D3D12_MESSAGE_SEVERITY MinLogLevel;

        /** \brief Specifies recording options.

        For example, what events to record, and where to record them.
        */
        RECORD_OPTIONS RecordOptions;

        /** \brief Specifies the adapter's tier of resource heap support.

        Used to determine if resource categories (texture and buffers) can co-exist in the
        same resource heap.

        Optional parameter. By default, max tier. Use CheckFeatureSupport.
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
        UINT64 PreferredResourceHeapSize;

        /** \brief Maximum size of the resource heap allowed.

        The maximum resource heap size is equal to the total virtual address range of memory
        available to the allocator.

        Optional parameter. When 0 is specified, the API will automatically set the max resource
        heap size based on the adapter's GPU virtual address range. If the max resource size
        exceeds the adapter's GPU virtual address range, it will default to the smaller range.
        */
        UINT64 MaxResourceHeapSize;

        /** \brief Resource heap fragmentation limit, expressed as a percentage of the resource heap
        size, that is acceptable to be wasted due to fragmentation.

        Fragmentation occurs when the allocation is larger then the resource size.
        This occurs when the type of resource (buffer or texture) and allocator have different
        alignment requirements. For example, a 192KB resource may need to allocate 256KB of
        allocated space, which is equivalent to a fragmentation limit of 33%.

        When PreferredResourceHeapSize is non-zero, the ResourceHeapFragmentationLimit could be
        exceeded. Also, the ResourceHeapFragmentationLimit should never be zero, as some
        fragmentation can occur.

        Optional parameter. When 0 is specified, the default fragmentation limit is 1/8th the
        resource heap size.
        */
        FLOAT ResourceHeapFragmentationLimit;

        /** \brief Resource heap growth factor, expressed as a multiple of the resource heap size
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
        FLOAT ResourceHeapGrowthFactor;
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
        ALLOCATION_FLAG_NEVER_ALLOCATE_HEAP = 0x1,

        /** \brief Sub-allocate a resource allocation within the same resource.

        The resource alignment is allowed to be byte-aligned instead of being resource-aligned,
        which significantly reduces app memory usage (1B vs 64KB per allocation). Since the resource
        can only be in one state at a time, this is mostly restricted to constant buffers (index and
        vertex buffers which will stay read-only after creation). The app developer must use offsets
        from the start of the allocation (vs subresource index) by using
        ResourceAllocation::GetOffsetFromResource().

        The app developer must either check if the allocator supports sub-allocation within resource
        beforehand (via ResourceAllocator::CheckFeatureSupport) OR simply ensure only a single
        command queue is used since not all devices guarantee command queue accesses are coherent
        between sub-allocations within the same resource.
        */
        ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE = 0x2,

        /** \brief Disallow allowing the creation of multiple resources using the same resource
        heap.

        When this flag is used, the created resource will always be allocated with it's own resource
        heap.
        */
        ALLOCATION_FLAG_NEVER_SUBALLOCATE_HEAP = 0x4,

        /** \brief Force pre-fetch for the next resource allocation.

        This flag has no effect if RESOURCE_ALLOCATOR_FLAG_ALLOW_PREFETCH was not specified.

        Should not be used with ALLOCATION_FLAG_NEVER_ALLOCATE_HEAP.
        */
        ALLOCATION_FLAG_ALWAYS_PREFETCH_HEAP = 0x8,

        /** \brief Cache the request size.

        Allow internal data structures used for resource allocation to be cached in-memory.
        */
        ALLOCATION_FLAG_ALWAYS_CACHE_SIZE = 0x10,

        /** \brief Requires heaps to be always attributed by D3D12_HEAP_TYPE.

        With cache-coherent UMA adapters, a single custom-equivalent heap will be used everywhere.
        This enables better resource optimization during allocation. However, certain heap flags or
        access-patterns may beneifit specifying D3D12_HEAP_TYPE. For example,
        D3D12_HEAP_FLAG_SHARED requires D3D12_HEAP_TYPE_READBACK or D3D12_HEAP_TYPE_UPLOAD,
        as well as frequent CPU reads would beneifit from D3D12_HEAP_TYPE_READBACK since the CPU
        properties are always write-combined.

        If RESOURCE_ALLOCATOR_FLAG_ALLOW_UNIFIED_MEMORY was not specified, heap type was
        D3D12_HEAP_TYPE_READBACK, or the adapter is not cache-coherent UMA, this flag has no effect.
        */
        ALLOCATION_FLAG_ALWAYS_ATTRIBUTE_HEAPS = 0x20,

        /** \brief Forces use of the resource allocator or E_FAIL.

        The flag disables the fall-back behavior of reverting to the D3D12 runtime/driver provided
        allocator (CreateCommittedResource) when resource allocation fails.

        Mostly used for debug and testing when certain allocation methods unexpectedly fail.
        */
        ALLOCATION_FLAG_NEVER_FALLBACK = 0x40,

        /** \brief Disable residency management for the resource allocation.

        The flag disables residency management for the resource allocation.

        Mostly used when external resources are residency managed elsewhere.
        */
        ALLOCATION_FLAG_NEVER_RESIDENT = 0x80,

        /** \brief Report alignment mismatches upon successful resource creation.

        Flag is used to report when requested size does not match the allocation size due to
        resource or allocation alignment requirements.

        Must compile with GPGMM_ENABLE_MEMORY_ALIGN_CHECKS to use as the request size
        is normally not tracked.
        */
        ALLOCATION_FLAG_ALWAYS_WARN_ON_ALIGNMENT_MISMATCH = 0x100,
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

        It is recommended to not specify the heap type or equivalently specify
        D3D12_HEAP_TYPE_CUSTOM. This enables better resource optimization for UMA adapters by using
        a custom-equivalent upload heap everywhere. However, since UMA adapters use write-combined
        memory for CPU writes, a heap type of D3D12_HEAP_TYPE_READBACK could have better
        performance.

        Optional parameter. If the heap type is not provided or D3D12_HEAP_TYPE_CUSTOM, the heap
        type will be inferred by using adapter properties and the initial resource state.
        */
        D3D12_HEAP_TYPE HeapType;

        /** \brief Additional heap flags that the resource requires.

        By default, GPGMM infers the required heap flags based on the required
        fields in the D3D12_RESOURCE_DESC, RESOURCE_ALLOCATOR_DESC and ALLOCATION_DESC.
        But if additional heap flags are required, they can also be specified.

        It is recommended to only specify D3D12_HEAP_FLAG_NONE since not all
        allocation methods are guaranteed to be supported.

        Optional parameter.
        */
        D3D12_HEAP_FLAGS ExtraRequiredHeapFlags;

        /** \brief Require additional bytes to be appended to the resource allocation.

        Resource heap size is guaranteed to increase by at-least this number of bytes.
        Specifying a padding will disable committed resources and sub-allocated
        heaps.

        Used to workaround driver bugs related to the heap size being insufficient for the resource.

        Optional parameter. No extra padding is applied by default.
        */
        UINT64 ExtraRequiredResourcePadding;

        /** \brief Associates a name with the given allocation.

        Optional parameter. By default, no name is associated.
        */
        LPCWSTR DebugName;
    };

    /** \struct FEATURE_DATA_RESOURCE_ALLOCATION_SUPPORT

    Details the resource allocator limitations, including if sharing resources between command
    queues is coherent.
    */
    struct FEATURE_DATA_RESOURCE_ALLOCATION_SUPPORT {
        /** \brief Describes resource within coherency behavior between command-queues.

        For example, if two allocations belong to the same resource where each allocation is
        referenced with a different command-queue, will accessing one stomp over the other. D3D12
        does not guarantee such behavior is safe but is it well-defined behavior based on the GPU
        vendor.
        */
        bool IsResourceAllocationWithinCoherent;
    };

    /** \enum ALLOCATOR_FEATURE

    Defines constants that specify a resource allocator feature to query about. When you
    want to query for the level to which an allocator supports a feature, pass one of these values
    to ResourceAllocator::CheckFeatureSupport.
    */
    enum ALLOCATOR_FEATURE {
        /** \brief Indicates a query for the level of support for allocated resources. The
        corresponding data structure for this value is FEATURE_DATA_RESOURCE_ALLOCATION_SUPPORT
        */
        ALLOCATOR_FEATURE_RESOURCE_ALLOCATION_SUPPORT,
    };

    /** \struct ALLOCATOR_STATS
    Additional information about allocator usage.
    */
    struct ALLOCATOR_STATS {
        /** \brief Number of used sub-allocated blocks within the same memory.
         */
        UINT UsedBlockCount;

        /** \brief Total size, in bytes, of used sub-allocated blocks.
         */
        UINT64 UsedBlockUsage;

        /** \brief Number of used memory allocations.
         */
        UINT UsedHeapCount;

        /** \brief Total size, in bytes, of used memory.
         */
        UINT64 UsedHeapUsage;

        /** \brief Total size, in bytes, of free memory.
         */
        UINT64 FreeHeapUsage;

        /** \brief Cache misses not eliminated by prefetching.
         */
        UINT64 PrefetchedHeapMisses;

        /** \brief Cache misses eliminated because of prefetching.
         */
        UINT64 PrefetchedHeapMissesEliminated;

        /** \brief Requested size was NOT cached.
         */
        UINT64 SizeCacheMisses;

        /** \brief Requested size was cached.
         */
        UINT64 SizeCacheHits;
    };

    /** \brief ResourceAllocator is an allocator that creates ID3D12Resources in a
    ResourceAllocation.

    Internally, ResourceAllocator creates a request, by determining the
    resource allocation requirements, then finds an allocator able to service the request.

    If the first ResourceAllocator attempt fails, it will try a second allocator, and so on.
    ResourceAllocator attempts are greedy: re-use of resources > re-use of heaps >
    re-use by pools > no re-use, in order of maximizing performance while minimizing memory
    footprint.

    ResourceAllocator also uses ResidencyManager to determine available memory
    (or budget left) when creating the request. This is because residency is managed
    per heap and not per resource). A larger Heap could be ideal for allocation but only if there is
    budget. And similarly, a smaller Heap allows for finer grained residency but could increase
    overall memory usage for allocation.
    **/
    GPGMM_INTERFACE IResourceAllocator : public IDebugObject {
      public:
        /** \brief  Allocates memory and creates a D3D12 resource using it.

        Returns a ResourceAllocation which represents a resource allocated at a specific
        location in memory. The resource could be allocated within a resource heap, within the
        resource itself, or separately using it's own memory (resource heap).

        Unlike a D3D12 resource, a resource allocation can made resident. It is recommended but not
        strictly required to use the D3D12 resource equivalent methods (ex. Map, Unmap) through the
        returned ResourceAllocation.

        @param allocationDescriptor A reference to ALLOCATION_DESC structure that provides
        properties for the resource allocation.
        @param resourceDescriptor A reference to the D3D12_RESOURCE_DESC structure that describes
        the resource.
        @param initialResourceState The initial state of the resource, a bitwise OR'd combination of
        D3D12_RESOURCE_STATES enumeration constants.
        @param pClearValue A pointer to D3D12_CLEAR_VALUE structure that describes the default value
        for a clear color.
        @param[out] ppResourceAllocationOut An optional pointer to a memory block that receives the
        required interface pointer to the created resource allocation object.
        */
        virtual HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                       const D3D12_RESOURCE_DESC& resourceDescriptor,
                                       D3D12_RESOURCE_STATES initialResourceState,
                                       const D3D12_CLEAR_VALUE* pClearValue,
                                       IResourceAllocation** ppResourceAllocationOut) = 0;

        /** \brief  Use existing D3D12 resource as a resource allocation.

        Returns a ResourceAllocation which represents an existing resource with a resource heap.

        @param allocationDescriptor A reference to ALLOCATION_DESC structure that provides.
        properties for the resource allocation.
        @param pCommittedResource A pointer to a committed ID3D12Resource.
        @param[out] ppResourceAllocationOut Pointer to a memory block that receives a pointer to the
        resource allocation. Pass NULL to test if resource allocation creation would succeed, but
        not actually create the resource allocation. If NULL is passed and resource allocation
        creation would succeed, S_FALSE is returned.
        */
        virtual HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                       ID3D12Resource* pCommittedResource,
                                       IResourceAllocation** ppResourceAllocationOut) = 0;

        /** \brief Return free memory back to the OS.

        When pooling is enabled, the allocator will retain resource heaps in order to speed-up
        subsequent resource allocation requests. These resource allocations count against the
        app's memory usage and in general, will lead to increased memory usage by the overall
        system. Apps should call ReleaseResourceHeaps() when going idle for a period of time since
        there is a brief performance hit when the internal resource heaps get reallocated by the OS.

        @param bytesToRelease Amount of memory to release, in bytes. A value of UINT64_MAX
        releases ALL memory held by the allocator.
        @param pBytesReleased Optional pointer to integer which receives the amount of memory
        released, in bytes.

        \return Returns S_OK if successfully released equal to or greater than the memory amount
        specified. Or S_FALSE if the released size was smaller, there was not enough memory or
        larger if releasable memory doesn't exactly total up to the amount.
        */
        virtual HRESULT ReleaseResourceHeaps(UINT64 bytesToRelease, UINT64 * pBytesReleased) = 0;

        /** \brief  Query the current allocator usage.

        Returned info can be used to monitor memory usage per allocator.
        For example, the amount of internal fragmentation is equal to UsedBlockUsage /
        UsedMemoryUsage. Or the percent of recycled memory is equal to FreeMemoryUsage /
        (UsedMemoryUsage + FreeMemoryUsage) * 100%.

        @param pResourceAllocatorStats A pointer to a ALLOCATOR_STATS structure or NULL if
        statistics information should only be gathered for recording.

        \return Returns S_OK if successful. Returns S_FALSE if statistics information was only
        gathered for recording.
        */
        virtual HRESULT QueryStats(ALLOCATOR_STATS * pResourceAllocatorStats) = 0;

        /** \brief Gets information about the features that are supported by the resource allocator.

        @param feature A constant from the ALLOCATOR_FEATURE enumeration describing the feature(s)
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
        virtual HRESULT CheckFeatureSupport(ALLOCATOR_FEATURE feature, void* pFeatureSupportData,
                                            UINT featureSupportDataSize) const = 0;
    };

    /** \brief Create a resource allocator with residency.

    Residency requires at-least DXGI version 1.4.

    @param allocatorDescriptor A reference to RESOURCE_ALLOCATOR_DESC structure that describes the
    allocator.
    @param pDevice device used by this allocator. Required parameter. Use CreateDevice get the
    device.
    @param pAdapter DXGI adapter used to create the device. Used to detect for additional device
    capabilities (by GPU vendor). Optional parameter. Use EnumAdapters to get the adapter.
    @param[out] ppResourceAllocatorOut Pointer to a memory block that receives a pointer to the
    resource allocator. Pass NULL to test if allocator creation would succeed, but not actually
    create the allocator.
    @param[out] ppResidencyManagerOut Pointer to a memory block that receives a pointer to the
    residency manager. If NULL is passed, the allocator will be created without using
    residency.
    */
    GPGMM_EXPORT HRESULT CreateResourceAllocator(const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
                                                 ID3D12Device* pDevice,
                                                 IDXGIAdapter* pAdapter,
                                                 IResourceAllocator** ppResourceAllocatorOut,
                                                 IResidencyManager** ppResidencyManagerOut);

    /** \brief Create a resource allocator using a specified residency manager.

    @param allocatorDescriptor A reference to RESOURCE_ALLOCATOR_DESC structure that describes the
    allocator.
    @param pDevice device used by this allocator. Required parameter. Use CreateDevice get the
    device.
    @param pAdapter DXGI adapter used to create the device. Used to detect for additional device
    capabilities (by GPU vendor). Optional parameter. Use EnumAdapters to get the adapter.
    @param pResidencyManager Pointer to a memory block that receives a pointer to the
    residency manager.
    @param[out] ppResourceAllocatorOut Pointer to a memory block that receives a pointer to the
    resource allocator. Pass NULL to test if allocator creation would succeed, but not actually
    create the allocator.
    */
    GPGMM_EXPORT HRESULT CreateResourceAllocator(const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
                                                 ID3D12Device* pDevice,
                                                 IDXGIAdapter* pAdapter,
                                                 IResidencyManager* pResidencyManager,
                                                 IResourceAllocator** ppResourceAllocatorOut);

}  // namespace gpgmm::d3d12

#endif  // INCLUDE_GPGMM_D3D12_H_
