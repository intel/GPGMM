// Copyright 2020 The Dawn Authors
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

#include "gpgmm/d3d12/ResidencyManagerD3D12.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/ThreadPool.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/FenceD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencyListD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/Math.h"

#include <algorithm>
#include <vector>

namespace gpgmm::d3d12 {

    static constexpr uint64_t kDefaultEvictSizeInBytes = GPGMM_MB_TO_BYTES(50);
    static constexpr float kDefaultMaxPctOfVideoMemoryToBudget = 0.95f;  // 95%
    static constexpr float kDefaultMinPctOfBudgetToReserve = 0.50f;      // 50%

    // Creates a long-lived task to recieve and process OS budget change events.
    class BudgetUpdateTask : public VoidCallback {
      public:
        BudgetUpdateTask(ResidencyManager* const residencyManager, IDXGIAdapter3* adapter)
            : mResidencyManager(residencyManager),
              mAdapter(std::move(adapter)),
              mBudgetNotificationUpdateEvent(CreateEventW(NULL, FALSE, FALSE, NULL)),
              mUnregisterAndExitEvent(CreateEventW(NULL, FALSE, FALSE, NULL)) {
            ASSERT(mResidencyManager != nullptr);
            ASSERT(mAdapter != nullptr);
            mLastError = mAdapter->RegisterVideoMemoryBudgetChangeNotificationEvent(
                mBudgetNotificationUpdateEvent, &mCookie);
        }

        void operator()() override {
            HRESULT hr = GetLastError();
            bool isExiting = false;
            while (!isExiting && SUCCEEDED(hr)) {
                // Wait on two events: one to unblock for OS budget changes, and another to unblock
                // for shutdown.
                HANDLE hWaitEvents[2] = {mBudgetNotificationUpdateEvent, mUnregisterAndExitEvent};
                const DWORD waitedEvent =
                    WaitForMultipleObjects(2, hWaitEvents, /*bWaitAll*/ false, INFINITE);
                switch (waitedEvent) {
                    // mBudgetNotificationUpdateEvent
                    case (WAIT_OBJECT_0 + 0): {
                        hr = mResidencyManager->UpdateMemorySegments();
                        if (FAILED(hr)) {
                            break;
                        }

                        gpgmm::DebugEvent(mResidencyManager, MessageId::kBudgetUpdated)
                            << "Updated budget from OS notification.";
                        break;
                    }
                    // mUnregisterAndExitEvent
                    case (WAIT_OBJECT_0 + 1): {
                        isExiting = true;
                        break;
                    }
                    default: {
                        UNREACHABLE();
                        break;
                    }
                }
            }

            if (FAILED(hr)) {
                gpgmm::ErrorLog() << "Unable to update budget: " +
                                         GetDeviceErrorMessage(mResidencyManager->mDevice, hr);
            }

            SetLastError(hr);
        }

        HRESULT GetLastError() const {
            std::lock_guard<std::mutex> lock(mMutex);
            return mLastError;
        }

        // Shutdown the event loop.
        bool UnregisterAndExit() {
            mAdapter->UnregisterVideoMemoryBudgetChangeNotification(mCookie);
            return SetEvent(mUnregisterAndExitEvent);
        }

      private:
        void SetLastError(HRESULT hr) {
            std::lock_guard<std::mutex> lock(mMutex);
            mLastError = hr;
        }

        ResidencyManager* const mResidencyManager;
        IDXGIAdapter3* mAdapter = nullptr;

        HANDLE mBudgetNotificationUpdateEvent = INVALID_HANDLE_VALUE;
        HANDLE mUnregisterAndExitEvent = INVALID_HANDLE_VALUE;

        DWORD mCookie = 0;  // Used to unregister from notifications.

        mutable std::mutex mMutex;  // Protect access between threads for members below.
        HRESULT mLastError = S_OK;
    };

    class BudgetUpdateEvent final : public Event {
      public:
        BudgetUpdateEvent(std::shared_ptr<Event> event, std::shared_ptr<BudgetUpdateTask> task)
            : mTask(task), mEvent(event) {
        }

        // Event overrides
        void Wait() override {
            mEvent->Wait();
        }

        bool IsSignaled() override {
            return mEvent->IsSignaled();
        }

        void Signal() override {
            return mEvent->Signal();
        }

        bool UnregisterAndExit() {
            return mTask->UnregisterAndExit();
        }

        bool GetLastError() const {
            return mTask->GetLastError();
        }

      private:
        std::shared_ptr<BudgetUpdateTask> mTask;
        std::shared_ptr<Event> mEvent;
    };

    HRESULT CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                   IResidencyManager** ppResidencyManagerOut) {
        return ResidencyManager::CreateResidencyManager(descriptor, ppResidencyManagerOut);
    }

    // static
    HRESULT ResidencyManager::CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                                     IResidencyManager** ppResidencyManagerOut) {
        ReturnIfNullptr(descriptor.Adapter);
        ReturnIfNullptr(descriptor.Device);

        std::unique_ptr<Caps> caps;
        {
            Caps* ptr = nullptr;
            ReturnIfFailed(Caps::CreateCaps(descriptor.Device, descriptor.Adapter, &ptr));
            caps.reset(ptr);
        }

        if ((descriptor.Flags & RESIDENCY_FLAG_DISABLE_UNIFIED_MEMORY) && caps->IsAdapterUMA()) {
            gpgmm::WarningLog() << "RESIDENCY_FLAG_DISABLE_UNIFIED_MEMORY flag was specified but "
                                   "did not match the architecture of the adapter.";
        }

        if (descriptor.MaxPctOfVideoMemoryToBudget != 0 && descriptor.MaxBudgetInBytes != 0) {
            gpgmm::ErrorLog() << "Both the OS based memory budget and restricted budget were "
                                 "specified but cannot be used at the same time.";
            return E_UNEXPECTED;
        }

        if (descriptor.RecordOptions.Flags != EventRecordFlags::kNone) {
            StartupEventTrace(descriptor.RecordOptions.TraceFile,
                              static_cast<TraceEventPhase>(~descriptor.RecordOptions.Flags));

            SetEventMessageLevel(GetMessageSeverity(descriptor.MinRecordLevel));
        }

        SetLogLevel(GetMessageSeverity(descriptor.MinLogLevel));

        std::unique_ptr<ResidencyManager> residencyManager =
            std::unique_ptr<ResidencyManager>(new ResidencyManager(descriptor, std::move(caps)));

        // Require automatic video memory budget updates.
        if (!(descriptor.Flags & RESIDENCY_FLAG_NEVER_UPDATE_BUDGET_ON_WORKER_THREAD)) {
            ReturnIfFailed(residencyManager->StartBudgetNotificationUpdates());
            gpgmm::DebugLog() << "OS based memory budget updates were successfully enabled.";
        }

        // Set the initial video memory limits.
        ReturnIfFailed(residencyManager->UpdateMemorySegments());

        DXGI_QUERY_VIDEO_MEMORY_INFO* localVideoMemorySegmentInfo =
            residencyManager->GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_LOCAL);

        DXGI_QUERY_VIDEO_MEMORY_INFO* nonLocalVideoMemorySegmentInfo =
            residencyManager->GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL);

        // D3D12 has non-zero memory usage even before any resources have been created, and this
        // value can vary by OS enviroment. By adding this in addition to the artificial budget
        // limit, we can create a predictable and reproducible budget.
        if (descriptor.MaxBudgetInBytes > 0) {
            localVideoMemorySegmentInfo->Budget =
                localVideoMemorySegmentInfo->CurrentUsage + descriptor.MaxBudgetInBytes;
            if (!residencyManager->mIsUMA) {
                nonLocalVideoMemorySegmentInfo->Budget =
                    nonLocalVideoMemorySegmentInfo->CurrentUsage + descriptor.MaxBudgetInBytes;
            }
        }

        // Emit a warning if the budget was initialized to zero.
        // This means nothing will be ever evicted, which will lead to device lost.
        if (localVideoMemorySegmentInfo->Budget == 0) {
            gpgmm::WarningLog()
                << "GPU memory segment ("
                << GetMemorySegmentName(DXGI_MEMORY_SEGMENT_GROUP_LOCAL, residencyManager->mIsUMA)
                << ") did not initialize a budget. This means either a restricted budget was not "
                   "used or the first OS budget update hasn't occured.";
            if (!residencyManager->mIsUMA && nonLocalVideoMemorySegmentInfo->Budget == 0) {
                gpgmm::WarningLog() << "GPU memory segment ("
                                    << GetMemorySegmentName(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                                                            residencyManager->mIsUMA)
                                    << ") did not initialize a budget. This means either a "
                                       "restricted budget was not "
                                       "used or the first OS budget update hasn't occured.";
            }
        }

        // Dump out the initialized memory segment status.
        residencyManager->ReportSegmentInfoForTesting(DXGI_MEMORY_SEGMENT_GROUP_LOCAL);
        if (!residencyManager->mIsUMA) {
            residencyManager->ReportSegmentInfoForTesting(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL);
        }

        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(residencyManager.get(), descriptor);

        if (ppResidencyManagerOut != nullptr) {
            *ppResidencyManagerOut = residencyManager.release();
        }

        return S_OK;
    }

    ResidencyManager::ResidencyManager(const RESIDENCY_DESC& descriptor, std::unique_ptr<Caps> caps)
        : mDevice(descriptor.Device),
          mAdapter(descriptor.Adapter),
          mMaxPctOfVideoMemoryToBudget(descriptor.MaxPctOfVideoMemoryToBudget == 0
                                           ? kDefaultMaxPctOfVideoMemoryToBudget
                                           : descriptor.MaxPctOfVideoMemoryToBudget),
          mMinPctOfBudgetToReserve(descriptor.MinPctOfBudgetToReserve == 0
                                       ? kDefaultMinPctOfBudgetToReserve
                                       : descriptor.MinPctOfBudgetToReserve),
          mIsBudgetRestricted(descriptor.MaxBudgetInBytes > 0),
          mEvictSizeInBytes(descriptor.EvictSizeInBytes == 0 ? kDefaultEvictSizeInBytes
                                                             : descriptor.EvictSizeInBytes),
          mIsUMA(caps->IsAdapterUMA() &&
                 !(descriptor.Flags & RESIDENCY_FLAG_DISABLE_UNIFIED_MEMORY)),
          mIsBudgetChangeEventsDisabled(descriptor.Flags &
                                        RESIDENCY_FLAG_NEVER_UPDATE_BUDGET_ON_WORKER_THREAD),
          mFlushEventBuffersOnDestruct(descriptor.RecordOptions.EventScope &
                                       EventRecordScope::kPerInstance),
          mInitialFenceValue(descriptor.InitialFenceValue) {
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);

        ASSERT(mDevice != nullptr);
        ASSERT(mAdapter != nullptr);
    }

    ResidencyManager::~ResidencyManager() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
        StopBudgetNotificationUpdates();

        if (mFlushEventBuffersOnDestruct) {
            FlushEventTraceToDisk();
        }
    }

    const char* ResidencyManager::GetTypename() const {
        return "ResidencyManager";
    }

    // Increments number of locks on a heap to ensure the heap remains resident.
    HRESULT ResidencyManager::LockHeap(IHeap* pHeap) {
        ReturnIfNullptr(pHeap);

        std::lock_guard<std::mutex> lock(mMutex);

        Heap* heap = static_cast<Heap*>(pHeap);
        ASSERT(heap != nullptr);

        if (!heap->IsInList() && !heap->IsResidencyLocked()) {
            ComPtr<ID3D12Pageable> pageable;
            ReturnIfFailed(heap->QueryInterface(IID_PPV_ARGS(&pageable)));
            ReturnIfFailed(MakeResident(heap->GetMemorySegmentGroup(), heap->GetSize(), 1,
                                        pageable.GetAddressOf()));
            heap->SetResidencyState(RESIDENCY_STATUS_CURRENT_RESIDENT);

            // Untracked heaps, created not resident, are not already attributed toward residency
            // usage because they are not in the residency cache.
            mStats.CurrentMemoryCount++;
            mStats.CurrentMemoryUsage += heap->GetSize();
        }

        // Since we can't evict the heap, it's unnecessary to track the heap in the LRU Cache.
        if (heap->IsInList()) {
            heap->RemoveFromList();

            // Untracked heaps, previously made resident, are not attributed toward residency usage
            // because they will be removed from the residency cache.
            if (heap->mState == RESIDENCY_STATUS_CURRENT_RESIDENT) {
                mStats.CurrentMemoryCount++;
                mStats.CurrentMemoryUsage += heap->GetSize();
            }
        }

        heap->AddResidencyLockRef();

        return S_OK;
    }

    // Decrements number of locks on a heap. When the number of locks becomes zero, the heap is
    // inserted into the LRU cache and becomes eligible for eviction.
    HRESULT ResidencyManager::UnlockHeap(IHeap* pHeap) {
        ReturnIfNullptr(pHeap);

        std::lock_guard<std::mutex> lock(mMutex);
        Heap* heap = static_cast<Heap*>(pHeap);
        ASSERT(heap != nullptr);

        // If the heap was never locked, nothing further should be done.
        if (!heap->IsResidencyLocked()) {
            return S_OK;
        }

        if (heap->IsInList()) {
            gpgmm::ErrorLog()
                << "Heap was never being tracked for residency. This usually occurs when a "
                   "non-resource heap was created by the developer and never made resident at "
                   "creation or failure to call LockHeap beforehand.";
            return E_FAIL;
        }

        heap->ReleaseResidencyLock();

        // If another lock still exists on the heap, nothing further should be done.
        if (heap->IsResidencyLocked()) {
            return S_OK;
        }

        // When all locks have been removed, the resource remains resident and becomes tracked in
        // the corresponding LRU.
        ReturnIfFailed(InsertHeapInternal(heap));

        // Heaps inserted into the residency cache are already attributed in residency usage.
        mStats.CurrentMemoryCount--;
        mStats.CurrentMemoryUsage -= heap->GetSize();

        return S_OK;
    }

    HRESULT ResidencyManager::InsertHeap(Heap* pHeap) {
        std::lock_guard<std::mutex> lock(mMutex);
        return InsertHeapInternal(pHeap);
    }

    // Inserts a heap at the bottom of the LRU. The passed heap must be resident or scheduled to
    // become resident within the current serial. Failing to call this function when an allocation
    // is implicitly made resident will cause the residency manager to view the allocation as
    // non-resident and call MakeResident - which will make D3D12's internal residency refcount on
    // the allocation out of sync with Dawn.
    HRESULT ResidencyManager::InsertHeapInternal(Heap* heap) {
        if (heap == nullptr) {
            return E_INVALIDARG;
        }

        // Heap already exists in the cache.
        if (heap->IsInList()) {
            return E_INVALIDARG;
        }

        LRUCache* cache = GetVideoMemorySegmentCache(heap->GetMemorySegmentGroup());
        ASSERT(cache != nullptr);

        heap->InsertAfter(cache->tail());

        ASSERT(heap->IsInList());

        return S_OK;
    }

    DXGI_QUERY_VIDEO_MEMORY_INFO* ResidencyManager::GetVideoMemoryInfo(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        switch (memorySegmentGroup) {
            case DXGI_MEMORY_SEGMENT_GROUP_LOCAL:
                return &mLocalVideoMemorySegment.Info;
            case DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL:
                return &mNonLocalVideoMemorySegment.Info;
            default:
                UNREACHABLE();
                return nullptr;
        }
    }

    ResidencyManager::LRUCache* ResidencyManager::GetVideoMemorySegmentCache(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        switch (memorySegmentGroup) {
            case DXGI_MEMORY_SEGMENT_GROUP_LOCAL:
                return &mLocalVideoMemorySegment.cache;
            case DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL:
                return &mNonLocalVideoMemorySegment.cache;
            default:
                UNREACHABLE();
                return nullptr;
        }
    }

    // Sends the minimum required physical video memory for an application, to this residency
    // manager. Returns the amount of memory reserved, which may be less then the |reservation| when
    // under video memory pressure.
    HRESULT ResidencyManager::SetVideoMemoryReservation(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
        uint64_t availableForReservation,
        uint64_t* pCurrentReservationOut) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "ResidencyManager.SetVideoMemoryReservation");

        std::lock_guard<std::mutex> lock(mMutex);

        DXGI_QUERY_VIDEO_MEMORY_INFO* videoMemorySegmentInfo =
            GetVideoMemoryInfo(memorySegmentGroup);

        videoMemorySegmentInfo->AvailableForReservation = availableForReservation;

        if (IsBudgetNotificationUpdatesDisabled()) {
            ReturnIfFailed(UpdateMemorySegmentInternal(memorySegmentGroup));
        }

        if (pCurrentReservationOut != nullptr) {
            *pCurrentReservationOut = videoMemorySegmentInfo->CurrentReservation;
        }

        return S_OK;
    }

    HRESULT ResidencyManager::UpdateMemorySegmentInternal(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        // For UMA adapters, non-local is always zero.
        if (mIsUMA && memorySegmentGroup == DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL) {
            return S_OK;
        }

        DXGI_QUERY_VIDEO_MEMORY_INFO queryVideoMemoryInfoOut;
        ReturnIfFailed(
            mAdapter->QueryVideoMemoryInfo(0, memorySegmentGroup, &queryVideoMemoryInfoOut));

        // The video memory budget provided by QueryVideoMemoryInfo is defined by the operating
        // system, and may be lower than expected in certain scenarios. Under memory pressure, we
        // cap the external reservation to half the available budget, which prevents the external
        // component from consuming a disproportionate share of memory and ensures forward progress.
        DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfo = GetVideoMemoryInfo(memorySegmentGroup);

        pVideoMemoryInfo->CurrentReservation = std::min(
            static_cast<uint64_t>(queryVideoMemoryInfoOut.Budget * mMinPctOfBudgetToReserve),
            pVideoMemoryInfo->AvailableForReservation);

        const uint64_t oldUsage = pVideoMemoryInfo->CurrentUsage;
        pVideoMemoryInfo->CurrentUsage =
            queryVideoMemoryInfoOut.CurrentUsage - pVideoMemoryInfo->CurrentReservation;

        if (oldUsage > pVideoMemoryInfo->CurrentUsage) {
            gpgmm::DebugLog() << GetMemorySegmentName(memorySegmentGroup, mIsUMA)
                              << " GPU memory usage went down by "
                              << GPGMM_BYTES_TO_MB(oldUsage - pVideoMemoryInfo->CurrentUsage)
                              << " MBs.";
        } else if (oldUsage < pVideoMemoryInfo->CurrentUsage) {
            gpgmm::DebugLog() << GetMemorySegmentName(memorySegmentGroup, mIsUMA)
                              << " GPU memory usage went up by "
                              << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentUsage - oldUsage)
                              << " MBs.";
        }

        // If we're restricting the budget, leave the budget as is.
        if (!mIsBudgetRestricted) {
            const uint64_t oldBudget = pVideoMemoryInfo->Budget;
            pVideoMemoryInfo->Budget = static_cast<uint64_t>(
                (queryVideoMemoryInfoOut.Budget - pVideoMemoryInfo->CurrentReservation) *
                mMaxPctOfVideoMemoryToBudget);

            if (oldBudget > pVideoMemoryInfo->Budget) {
                gpgmm::DebugLog() << GetMemorySegmentName(memorySegmentGroup, mIsUMA)
                                  << " GPU memory budget went down by "
                                  << GPGMM_BYTES_TO_MB(oldBudget - pVideoMemoryInfo->Budget)
                                  << " MBs.";
            } else if (oldBudget < pVideoMemoryInfo->Budget) {
                gpgmm::DebugLog() << GetMemorySegmentName(memorySegmentGroup, mIsUMA)
                                  << " GPU memory budget went up by "
                                  << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->Budget - oldBudget)
                                  << " MBs.";
            }
        }

        // Ignore when no budget was specified.
        if (pVideoMemoryInfo->Budget > 0 &&
            pVideoMemoryInfo->CurrentUsage > pVideoMemoryInfo->Budget) {
            WarnEvent(this, MessageId::kBudgetExceeded)
                << GetMemorySegmentName(memorySegmentGroup, mIsUMA)
                << " GPU memory exceeds budget: "
                << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentUsage) << " vs "
                << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->Budget) << " MBs.";
        }

        // Not all segments could be used.
        GPGMM_TRACE_EVENT_METRIC(
            ToString(GetMemorySegmentName(memorySegmentGroup, mIsUMA),
                     " GPU memory utilization (%)")
                .c_str(),
            (pVideoMemoryInfo->CurrentUsage > pVideoMemoryInfo->Budget)
                ? 100
                : SafeDivide(pVideoMemoryInfo->CurrentUsage, pVideoMemoryInfo->Budget) * 100);

        // Reservations are optional.
        GPGMM_TRACE_EVENT_METRIC(
            ToString(GetMemorySegmentName(memorySegmentGroup, mIsUMA), " GPU memory reserved (MB)")
                .c_str(),
            GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentReservation));

        return S_OK;
    }

    HRESULT ResidencyManager::UpdateMemorySegments() {
        std::lock_guard<std::mutex> lock(mMutex);
        ReturnIfFailed(UpdateMemorySegmentInternal(DXGI_MEMORY_SEGMENT_GROUP_LOCAL));
        ReturnIfFailed(UpdateMemorySegmentInternal(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL));
        return S_OK;
    }

    HRESULT ResidencyManager::QueryVideoMemoryInfo(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
        DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfoOut) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (IsBudgetNotificationUpdatesDisabled()) {
            ReturnIfFailed(UpdateMemorySegmentInternal(memorySegmentGroup));
        }

        if (pVideoMemoryInfoOut != nullptr) {
            *pVideoMemoryInfoOut = *GetVideoMemoryInfo(memorySegmentGroup);
        }

        return S_OK;
    }

    HRESULT ResidencyManager::EnsureInBudget(uint64_t bytesInBudget,
                                             const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        std::lock_guard<std::mutex> lock(mMutex);
        uint64_t bytesEvicted = bytesInBudget;
        ReturnIfFailed(EvictInternal(bytesInBudget, memorySegmentGroup, &bytesEvicted));
        return (bytesEvicted >= bytesInBudget) ? S_OK : E_FAIL;
    }

    // Evicts |evictSizeInBytes| bytes of memory in |memorySegmentGroup| and returns the number of
    // bytes evicted.
    HRESULT ResidencyManager::EvictInternal(uint64_t bytesToEvict,
                                            const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                            uint64_t* bytesEvictedOut) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "ResidencyManager.Evict");

        DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfo = GetVideoMemoryInfo(memorySegmentGroup);
        if (IsBudgetNotificationUpdatesDisabled()) {
            ReturnIfFailed(UpdateMemorySegmentInternal(memorySegmentGroup));
        }

        // If a budget wasn't provided, it not possible to evict. This is because either the budget
        // update event has not happened yet or was invalid.
        if (pVideoMemoryInfo->Budget == 0) {
            WarnEvent(this, MessageId::kBudgetInvalid)
                << "GPU memory segment ("
                << GetMemorySegmentName(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL, IsUMA())
                << ") was unable to evict memory because a budget was not specified.";
            return S_FALSE;
        }

        const uint64_t currentUsageAfterEvict = bytesToEvict + pVideoMemoryInfo->CurrentUsage;

        // Return if we will remain under budget after evict.
        if (currentUsageAfterEvict < pVideoMemoryInfo->Budget) {
            return S_OK;
        }

        // Any time we need to make something resident, we must check that we have enough free
        // memory to make the new object resident while also staying within budget. If there isn't
        // enough memory, we should evict until there is.
        std::vector<ID3D12Pageable*> objectsToEvict;
        const uint64_t bytesNeededToBeUnderBudget =
            currentUsageAfterEvict - pVideoMemoryInfo->Budget;

        // Return if nothing needs to be evicted to stay within budget.
        if (bytesNeededToBeUnderBudget == 0) {
            return S_OK;
        }

        ReturnIfFailed(EnsureResidencyFenceExists());

        uint64_t bytesEvicted = 0;
        while (bytesEvicted < bytesNeededToBeUnderBudget) {
            // If the cache is empty, allow execution to continue. Note that fully
            // emptying the cache is undesirable, because it can mean either 1) the cache is not
            // accurately accounting for GPU allocations, or 2) an external component is
            // using all of the budget and is starving us, which will cause thrash.
            LRUCache* cache = GetVideoMemorySegmentCache(memorySegmentGroup);
            ASSERT(cache != nullptr);

            if (cache->empty()) {
                break;
            }

            Heap* heap = cache->head()->value();
            const uint64_t lastUsedFenceValue = heap->GetLastUsedFenceValue();

            // If the next candidate for eviction was inserted into the cache during the current
            // submission, it is because more memory is being used in a single command list than is
            // available. In this scenario, we cannot make any more resources resident and thrashing
            // must occur.
            if (lastUsedFenceValue == mResidencyFence->GetCurrentFence()) {
                break;
            }

            // We must ensure that any previous use of a resource has completed before the resource
            // can be evicted.
            ReturnIfFailed(mResidencyFence->WaitFor(lastUsedFenceValue));

            heap->RemoveFromList();
            heap->SetResidencyState(RESIDENCY_STATUS_PENDING_RESIDENCY);

            bytesEvicted += heap->GetSize();

            ComPtr<ID3D12Pageable> pageable;
            ReturnIfFailed(heap->QueryInterface(IID_PPV_ARGS(&pageable)));

            objectsToEvict.push_back(pageable.Get());
        }

        if (objectsToEvict.size() > 0) {
            GPGMM_TRACE_EVENT_METRIC("GPU memory page-out (MB)", GPGMM_BYTES_TO_MB(bytesEvicted));

            const uint32_t objectEvictCount = static_cast<uint32_t>(objectsToEvict.size());
            ReturnIfFailed(mDevice->Evict(objectEvictCount, objectsToEvict.data()));

            DebugEvent(this, MessageId::kBudgetExceeded)
                << "GPU page-out. Number of allocations: " << objectsToEvict.size() << " ("
                << bytesEvicted << " bytes).";
        }

        if (bytesEvictedOut != nullptr) {
            *bytesEvictedOut = bytesEvicted;
        }

        return S_OK;
    }

    // Given a list of heaps that are pending usage, this function will estimate memory needed,
    // evict resources until enough space is available, then make resident any heaps scheduled for
    // usage.
    HRESULT ResidencyManager::ExecuteCommandLists(ID3D12CommandQueue* pQueue,
                                                  ID3D12CommandList* const* ppCommandLists,
                                                  IResidencyList* const* ppResidencyLists,
                                                  uint32_t count) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "ResidencyManager.ExecuteCommandLists");

        std::lock_guard<std::mutex> lock(mMutex);

        if (count == 0) {
            gpgmm::ErrorLog() << "ExecuteCommandLists is required to have at-least one residency "
                                 "list to be called.";
            return E_INVALIDARG;
        }

        // TODO: support multiple command lists.
        if (count > 1) {
            gpgmm::ErrorLog()
                << "ExecuteCommandLists does not support multiple residency lists at this time. "
                   "Please call ExecuteCommandLists per residency list as a workaround, if needed.";
            return E_NOTIMPL;
        }

        ReturnIfFailed(EnsureResidencyFenceExists());

        ResidencyList* residencyList = static_cast<ResidencyList*>(ppResidencyLists[0]);

        std::vector<ID3D12Pageable*> localHeapsToMakeResident;
        std::vector<ID3D12Pageable*> nonLocalHeapsToMakeResident;
        uint64_t localSizeToMakeResident = 0;
        uint64_t nonLocalSizeToMakeResident = 0;

        std::vector<Heap*> heapsToMakeResident;
        for (Heap* heap : *residencyList) {
            // Heaps that are locked resident are not tracked in the LRU cache.
            if (heap->IsResidencyLocked()) {
                continue;
            }

            // ResidencyList can contain duplicates. We can skip them by checking if the heap's last
            // used fence is the same as the current one.
            if (heap->GetLastUsedFenceValue() == mResidencyFence->GetCurrentFence()) {
                continue;
            }

            if (heap->IsInList()) {
                // If the heap is already in the LRU, we must remove it and append again below to
                // update its position in the LRU.
                heap->RemoveFromList();
            } else {
                ComPtr<ID3D12Pageable> pageable;
                ReturnIfFailed(heap->QueryInterface(IID_PPV_ARGS(&pageable)));

                if (heap->GetMemorySegmentGroup() == DXGI_MEMORY_SEGMENT_GROUP_LOCAL) {
                    localSizeToMakeResident += heap->GetSize();
                    localHeapsToMakeResident.push_back(pageable.Get());
                } else {
                    nonLocalSizeToMakeResident += heap->GetSize();
                    nonLocalHeapsToMakeResident.push_back(pageable.Get());
                }
            }

            // If we submit a command list to the GPU, we must ensure that heaps referenced by that
            // command list stay resident at least until that command list has finished execution.
            // Setting this serial unnecessarily can leave the LRU in a state where nothing is
            // eligible for eviction, even though some evictions may be possible.
            heap->SetLastUsedFenceValue(mResidencyFence->GetCurrentFence());

            // Insert the heap into the appropriate LRU.
            InsertHeapInternal(heap);

            // Temporarily track which heaps will be made resident. Once MakeResident() is called
            // on them will we transition them all together.
            heapsToMakeResident.push_back(heap);

            // If the heap should be already resident, calling MakeResident again will be redundant.
            // Tell the developer the heap wasn't properly tracked by the residency manager.
            if (heap->GetInfo().Status == RESIDENCY_STATUS_UNKNOWN) {
                gpgmm::DebugLog()
                    << "Residency state could not be determined for the heap (Heap="
                    << ToHexStr(heap)
                    << "). This likely means the developer was attempting to make a "
                       "non-resource heap resident without calling lock/unlock first.";
            }
        }

        if (localSizeToMakeResident > 0) {
            const uint32_t numberOfObjectsToMakeResident =
                static_cast<uint32_t>(localHeapsToMakeResident.size());
            ReturnIfFailed(MakeResident(DXGI_MEMORY_SEGMENT_GROUP_LOCAL, localSizeToMakeResident,
                                        numberOfObjectsToMakeResident,
                                        localHeapsToMakeResident.data()));
        } else if (nonLocalSizeToMakeResident > 0) {
            const uint32_t numberOfObjectsToMakeResident =
                static_cast<uint32_t>(nonLocalHeapsToMakeResident.size());
            ReturnIfFailed(MakeResident(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                                        nonLocalSizeToMakeResident, numberOfObjectsToMakeResident,
                                        nonLocalHeapsToMakeResident.data()));
        }

        // Once MakeResident succeeds, we must assume the heaps are resident since D3D12 provides
        // no way of knowing for certain.
        for (Heap* heap : heapsToMakeResident) {
            heap->SetResidencyState(RESIDENCY_STATUS_CURRENT_RESIDENT);
        }

        GPGMM_TRACE_EVENT_METRIC(
            "GPU memory page-in (MB)",
            GPGMM_BYTES_TO_MB(localSizeToMakeResident + nonLocalSizeToMakeResident));

        // Queue and command-lists may not be specified since they are not capturable for playback.
        if (ppCommandLists != nullptr && pQueue != nullptr) {
            pQueue->ExecuteCommandLists(count, ppCommandLists);
        }

        // If the queue was only specified, it likely means the application developer wants to call
        // ExecuteCommandLists themself. We must continue to keep the residency state of heaps
        // synchronized with the GPU in either case.
        if (pQueue != nullptr) {
            ReturnIfFailed(mResidencyFence->Signal(pQueue));
        }

        // Keep video memory segments up-to-date. This must always happen because if the budget
        // never changes (ie. not manually updated or through budget change events), the
        // residency manager wouldn't know what to page in or out.
        if (IsBudgetNotificationUpdatesDisabled()) {
            ReturnIfFailed(UpdateMemorySegmentInternal(DXGI_MEMORY_SEGMENT_GROUP_LOCAL));
            ReturnIfFailed(UpdateMemorySegmentInternal(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL));
        }

        GPGMM_TRACE_EVENT_OBJECT_CALL("ResidencyManager.ExecuteCommandLists",
                                      (EXECUTE_COMMAND_LISTS_DESC{ppResidencyLists, count}));

        return S_OK;
    }

    HRESULT ResidencyManager::MakeResident(const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup,
                                           uint64_t sizeToMakeResident,
                                           uint32_t numberOfObjectsToMakeResident,
                                           ID3D12Pageable** allocations) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "ResidencyManager.MakeResident");

        ReturnIfFailed(EvictInternal(sizeToMakeResident, memorySegmentGroup, nullptr));

        DebugEvent(this, MessageId::kBudgetExceeded)
            << "GPU page-in. Number of allocations: " << numberOfObjectsToMakeResident << " ("
            << sizeToMakeResident << " bytes).";

        // Decrease the overhead from using MakeResident, a synchronous call, by calling the
        // asynchronous MakeResident, called EnqueueMakeResident, instead first. Should
        // EnqueueMakeResident fail, fall-back to using synchronous MakeResident since we may be
        // able to continue after calling Evict again.
        ComPtr<ID3D12Device3> device3;
        if (SUCCEEDED(mDevice->QueryInterface(IID_PPV_ARGS(&device3)))) {
            ReturnIfFailed(EnsureResidencyFenceExists());
            ReturnIfSucceeded(device3->EnqueueMakeResident(
                D3D12_RESIDENCY_FLAG_NONE, numberOfObjectsToMakeResident, allocations,
                mResidencyFence->GetFence(), mResidencyFence->GetLastSignaledFence() + 1));
        }

        // A MakeResident call can fail if there's not enough available memory. This
        // could occur when there's significant fragmentation or if the allocation size
        // estimates are incorrect. We may be able to continue execution by evicting some
        // more memory and calling MakeResident again.
        while (FAILED(mDevice->MakeResident(numberOfObjectsToMakeResident, allocations))) {
            // If nothing can be evicted after MakeResident has failed, we cannot continue
            // execution and must throw a fatal error.
            uint64_t evictedSizeInBytes = 0;
            ReturnIfFailed(
                EvictInternal(mEvictSizeInBytes, memorySegmentGroup, &evictedSizeInBytes));
            if (evictedSizeInBytes == 0) {
                gpgmm::ErrorLog() << "Unable to evict enough heaps to stay within budget. This "
                                     "usually occurs when there is not enough available memory. "
                                     "Please reduce consumption by checking allocation sizes and "
                                     "residency usage.";
                return E_OUTOFMEMORY;
            }
        }

        return S_OK;
    }

    RESIDENCY_STATS ResidencyManager::GetStats() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return GetStatsInternal();
    }

    RESIDENCY_STATS ResidencyManager::GetStatsInternal() const {
        TRACE_EVENT0(TraceEventCategory::kDefault, "ResidencyManager.GetStats");

        // Heaps inserted into the residency cache are not resident until MakeResident() is called
        // on them. This occurs if the heap was created resident, heap gets locked, or call to
        // ExecuteCommandLists().

        // Locked heaps are not stored in the residency cache, so usage must be tracked by the
        // residency manager on Lock/Unlock then added here to get the sum.
        RESIDENCY_STATS result = mStats;

        for (const auto& entry : mLocalVideoMemorySegment.cache) {
            if (entry.value()->GetInfo().Status == RESIDENCY_STATUS_CURRENT_RESIDENT) {
                result.CurrentMemoryUsage += entry.value()->GetSize();
                result.CurrentMemoryCount++;
            }
        }

        for (const auto& entry : mNonLocalVideoMemorySegment.cache) {
            if (entry.value()->GetInfo().Status == RESIDENCY_STATUS_CURRENT_RESIDENT) {
                result.CurrentMemoryUsage += entry.value()->GetSize();
                result.CurrentMemoryCount++;
            }
        }

        GPGMM_TRACE_EVENT_METRIC("GPU currently resident (MB)",
                                 GPGMM_BYTES_TO_MB(result.CurrentMemoryUsage));

        return result;
    }

    // Starts updating video memory budget from OS notifications.
    // Return True if successfully registered or False if error.
    HRESULT ResidencyManager::StartBudgetNotificationUpdates() {
        if (mBudgetNotificationUpdateEvent == nullptr) {
            std::shared_ptr<BudgetUpdateTask> task =
                std::make_shared<BudgetUpdateTask>(this, mAdapter);
            mBudgetNotificationUpdateEvent = std::make_shared<BudgetUpdateEvent>(
                TaskScheduler::GetOrCreateInstance()->PostTask(task), task);
        }

        ASSERT(mBudgetNotificationUpdateEvent != nullptr);
        return mBudgetNotificationUpdateEvent->GetLastError();
    }

    bool ResidencyManager::IsBudgetNotificationUpdatesDisabled() const {
        return mIsBudgetChangeEventsDisabled ||
               (mBudgetNotificationUpdateEvent != nullptr &&
                FAILED(mBudgetNotificationUpdateEvent->GetLastError()));
    }

    void ResidencyManager::StopBudgetNotificationUpdates() {
        if (mBudgetNotificationUpdateEvent == nullptr) {
            return;
        }

        const bool success = mBudgetNotificationUpdateEvent->UnregisterAndExit();
        ASSERT(success);

        mBudgetNotificationUpdateEvent->Wait();
        mBudgetNotificationUpdateEvent = nullptr;
    }

    bool ResidencyManager::IsUMA() const {
        return mIsUMA;
    }

    void ResidencyManager::ReportSegmentInfoForTesting(DXGI_MEMORY_SEGMENT_GROUP segmentGroup) {
        DXGI_QUERY_VIDEO_MEMORY_INFO* info = GetVideoMemoryInfo(segmentGroup);
        ASSERT(info != nullptr);

        gpgmm::DebugLog() << GetMemorySegmentName(segmentGroup, IsUMA()) << " GPU memory segment:";
        gpgmm::DebugLog() << "\tBudget: " << GPGMM_BYTES_TO_MB(info->Budget) << " MBs ("
                          << GPGMM_BYTES_TO_MB(info->CurrentUsage) << " used).";

        if (info->CurrentReservation == 0) {
            gpgmm::DebugLog() << "\tReserved: " << GPGMM_BYTES_TO_MB(info->CurrentReservation)
                              << " MBs (" << GPGMM_BYTES_TO_MB(info->AvailableForReservation)
                              << " available).";
        }
    }

    HRESULT ResidencyManager::SetResidencyState(IHeap* pHeap, const RESIDENCY_STATUS& state) {
        ReturnIfNullptr(pHeap);

        Heap* heap = static_cast<Heap*>(pHeap);
        if (heap->GetInfo().IsLocked) {
            gpgmm::ErrorLog() << "Heap residency cannot be updated because it was locked. "
                                 "Please unlock the heap before updating the state.";
            return E_FAIL;
        }

        if (!heap->GetInfo().IsCachedForResidency) {
            gpgmm::ErrorLog() << "Heap residency cannot be updated because no residency "
                                 "manager was specified upon creation. The heap must be created "
                                 "using a residency manager to update the residency status.";
            return E_FAIL;
        }

        const RESIDENCY_STATUS oldState = heap->GetInfo().Status;
        if (state == RESIDENCY_STATUS_UNKNOWN && oldState != RESIDENCY_STATUS_UNKNOWN) {
            gpgmm::ErrorLog() << "Heap residency cannot be unknown when previously known by the "
                                 "residency manager. "
                                 "Check the status before updating the state.";
            return E_FAIL;
        }

        heap->SetResidencyState(state);
        return S_OK;
    }

    // Residency fence is lazily created to workaround an issue where adding another ref to the
    // device upon CreateFence and storing |this| on that device via SetPrivateData,
    // prevents the created device from ever being released.
    HRESULT ResidencyManager::EnsureResidencyFenceExists() {
        if (mResidencyFence != nullptr) {
            return S_OK;
        }

        Fence* fencePtr = nullptr;
        ReturnIfFailed(Fence::CreateFence(mDevice, mInitialFenceValue, &fencePtr));
        mResidencyFence.reset(fencePtr);
        return S_OK;
    }

}  // namespace gpgmm::d3d12
