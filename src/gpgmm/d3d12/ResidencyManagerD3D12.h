// Copyright 2020 The Dawn Authors
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

#ifndef GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
#define GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_

#include "gpgmm/d3d12/EventRecordD3D12.h"
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "gpgmm/utils/LinkedList.h"
#include "include/gpgmm_export.h"

#include <memory>
#include <mutex>

namespace gpgmm {
    class ThreadPool;
}  // namespace gpgmm

namespace gpgmm::d3d12 {

    class BudgetUpdateTask;
    class Fence;
    class Heap;
    class ResidencyList;
    class ResourceAllocator;
    class ResourceHeapAllocator;

    /** \struct RESIDENCY_DESC
     Specify parameters when creating a residency manager.
     */
    struct RESIDENCY_DESC {
        /** \brief Specifies the device used by this residency manager.
        Required parameter. Use CreateDevice get the device.
        */
        Microsoft::WRL::ComPtr<ID3D12Device> Device;

        /** \brief Specifies the adapter used by this residency manager.

        Requires DXGI 1.4 due to IDXGIAdapter3::QueryVideoMemoryInfo.

        Required parameter. Use EnumAdapters to get the adapter.
        */
        Microsoft::WRL::ComPtr<IDXGIAdapter3> Adapter;

        /** \brief Specifies if unified memory architecture (UMA) support is enabled.

        Used to determine if residency manager must manage local and non-local segments seperately
        or not.

        Required parameter. Use CheckFeatureSupport to determine if supported.
        */
        bool IsUMA;

        /** \brief Minimum severity level to log messages to console.

        Messages with lower severity will be ignored.

        Optional parameter. By default, will log only corruption messages.
        */
        D3D12_MESSAGE_SEVERITY MinLogLevel;

        /** \brief Specifies recording options.

        For example, what events to record, and where to record them.

        Optional parameter. By default, no options are specified for recording.
        */
        EVENT_RECORD_OPTIONS RecordOptions;

        /** \brief Maximum amount of budgeted memory, expressed as a percentage of video memory,
        that can be budgeted.

        If a non-zero MaxBudgetInBytes is specified, MaxPctOfVideoMemoryToBudget is ignored.

        Optional parameter. By default, the API will automatically set the budget to 95% of video
        memory, leaving 5% for the OS and other applications.
        */
        float MaxPctOfVideoMemoryToBudget;

        /** \brief Lowest amount of budgeted memory, expressed as a percentage, that can be
        reserved.

        If SetVideoMemoryReservation is used a set a reservation larger then the budget, this amount
        is used instead so the application can make forward progress.

        Optional parameter. By default, the API restricts the residency manager reservation to never
        go below 50% of the budget.
        */
        float MinPctOfBudgetToReserve;

        /** \brief Maximum amount of budgeted memory, in bytes, that can be budgeted.

        Allows a fixed budget to be artifically set for testing purposes.

        Optional parameter. By default, the API will not further restrict the residency manager
        budget.
        */
        uint64_t MaxBudgetInBytes;

        /** \brief Size of memory, in bytes, to evict from residency at once,
        should there not be enough budget left.

        Optional parameter. When 0 is specified, the API will use a evict size of 50MB.
        */
        uint64_t EvictSizeInBytes;

        /** \brief Initial fence value to use when managing heaps for residency.

        Fence value gets assigned to each managed heap and increments each time ExecuteCommandList()
        is called. When over budget, these fence values are compared to determine which heaps can be
        evicted.

        Optional parameter. Zero by default.
        */
        uint64_t InitialFenceValue;

        /** \brief Disables video memory budget updates from OS notifications.

        Used for polling video memory for budget updates when event based budget
        changes are not updating frequently enough or otherwise disabled by the OS.

        Optional parameter. Polling is disabled by default.
        */
        bool UpdateBudgetByPolling;
    };

    /** \struct RESIDENCY_INFO
    Additional information about the residency manager.
    */
    struct RESIDENCY_INFO {
        /** \brief Amount of memory, in bytes, made resident.
         */
        uint64_t ResidentMemoryUsage;

        /** \brief Number of heaps, made resident.
         */
        uint64_t ResidentMemoryCount;
    };

    class BudgetUpdateEvent;

    /** \brief ResidencyManager tracks and maintains one or more Heap within a residency cache.

    A Heap is considered "resident" when it is accessible by the GPU. A Heap can be made explicitly
    resident by calling ResidencyManager::LockHeap or implicitly resident by using the Heap with a
    ResidencyList upon calling ResidencyManager::ExecuteCommandLists or through a
    operation that always requires the Heap to be resident (eg. Map, Unmap).

    Internally, the ResidencyManager keeps the application in-budget by calling ID3D12Device::Evict
    and ID3D12Device::MakeResident to page-out or page-in heaps, respectively.
    **/
    class GPGMM_EXPORT ResidencyManager final : public IUnknownImpl {
      public:
        /** \brief  Create residency residency manager to manage video memory.

        @param descriptor A reference to RESIDENCY_DESC structure that describes the residency
        manager.
        @param[out] ppResidencyManagerOut Pointer to a memory block that recieves a pointer to the
        residency manager. Pass NULL to test if residency Manager creation would succeed, but not
        actually create the residency Manager. If NULL is passed and residency manager creating
        would succeed, S_FALSE is returned.
        */
        static HRESULT CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                              ResidencyManager** ppResidencyManagerOut);

        ~ResidencyManager() override;

        /** \brief  Locks the specified heap.

        Locking a heap means the residency manager will never evict it when over budget.

        @param pHeap A pointer to the heap being locked.
        */
        HRESULT LockHeap(Heap* pHeap);

        /** \brief  Unlocks the specified heap.

        Unlocking a heap allows the residency manager will evict it when over budget.

        @param pHeap A pointer to the heap being unlocked.
        */
        HRESULT UnlockHeap(Heap* pHeap);

        /** \brief  Execute command lists using residency managed heaps.

        Submits an array of command lists and residency lists for the specified command queue.

        @param pQueue The command queue to submit to.
        @param ppCommandLists The array of ID3D12CommandList command lists to be executed.
        @param ppResidencyLists The array of ResidencyList residency lists to make resident.
        @param count The size of commandLists and residencyLists arrays.
        */
        HRESULT ExecuteCommandLists(ID3D12CommandQueue* pQueue,
                                    ID3D12CommandList* const* ppCommandLists,
                                    ResidencyList* const* ppResidencyLists,
                                    uint32_t count);

        /** \brief  Sets video memory reservation.

        A reservation is the lowest amount of physical memory the application need to continue
        operation safely.

        @param memorySegmentGroup Memory segment to reserve.
        @param availableForReservation Amount of memory to reserve, in bytes.
        @param[out] pCurrentReservationOut the amount of memory reserved, which may be less then the
        |reservation| when under video memory pressure.
        */
        HRESULT SetVideoMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                          uint64_t availableForReservation,
                                          uint64_t* pCurrentReservationOut = nullptr);

        /** \brief  Get the current budget and memory usage.

        @param memorySegmentGroup Memory segment to retrieve info from.
        @param[out] pVideoMemoryInfoOut Pointer to DXGI_QUERY_VIDEO_MEMORY_INFO to populate.
        */
        HRESULT QueryVideoMemoryInfo(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                     DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfoOut);

        /** \brief  Return the current residency manager usage.

        \return A RESIDENCY_INFO struct.
        */
        RESIDENCY_INFO GetInfo() const;

      private:
        friend Heap;
        friend ResourceAllocator;
        friend ResourceHeapAllocator;

        ResidencyManager(const RESIDENCY_DESC& descriptor, std::unique_ptr<Fence> residencyFence);

        HRESULT EnsureInBudget(uint64_t bytesToEvict,
                               const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        HRESULT EvictInternal(uint64_t bytesToEvict,
                              const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                              uint64_t* bytesEvictedOut = nullptr);

        HRESULT InsertHeap(Heap* heap);

        HRESULT InsertHeapInternal(Heap* heap);

        friend BudgetUpdateTask;
        HRESULT UpdateMemorySegments();

        DXGI_MEMORY_SEGMENT_GROUP GetMemorySegmentGroup(D3D12_MEMORY_POOL memoryPool) const;

        const char* GetTypename() const;

        using LRUCache = LinkedList<Heap>;

        struct VideoMemorySegment {
            LRUCache cache = {};
            DXGI_QUERY_VIDEO_MEMORY_INFO Info = {};
        };

        HRESULT MakeResident(const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup,
                             uint64_t sizeToMakeResident,
                             uint32_t numberOfObjectsToMakeResident,
                             ID3D12Pageable** allocations);

        LRUCache* GetVideoMemorySegmentCache(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        DXGI_QUERY_VIDEO_MEMORY_INFO* GetVideoMemoryInfo(
            const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        HRESULT UpdateMemorySegmentInternal(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        HRESULT StartBudgetNotificationUpdates();
        void StopBudgetNotificationUpdates();

        bool IsBudgetNotificationUpdatesDisabled() const;

        ComPtr<ID3D12Device> mDevice;
        ComPtr<IDXGIAdapter3> mAdapter;
        ComPtr<ID3D12Device3> mDevice3;

        const float mMaxPctOfVideoMemoryToBudget;
        const float mMinPctOfBudgetToReserve;
        const bool mIsBudgetRestricted;
        const uint64_t mEvictSizeInBytes;
        const bool mIsUMA;
        const bool mIsBudgetChangeEventsDisabled;
        const bool mFlushEventBuffersOnDestruct;

        std::mutex mMutex;

        std::unique_ptr<Fence> mResidencyFence;

        VideoMemorySegment mLocalVideoMemorySegment;
        VideoMemorySegment mNonLocalVideoMemorySegment;
        RESIDENCY_INFO mInfo = {};

        std::shared_ptr<ThreadPool> mThreadPool;
        std::shared_ptr<BudgetUpdateEvent> mBudgetNotificationUpdateEvent;
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
