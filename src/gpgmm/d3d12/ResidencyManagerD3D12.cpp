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
#include "gpgmm/d3d12/BudgetUpdateD3D12.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/EventMessageD3D12.h"
#include "gpgmm/d3d12/FenceD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/LogD3D12.h"
#include "gpgmm/d3d12/ResidencyHeapD3D12.h"
#include "gpgmm/d3d12/ResidencyListD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/Math.h"

#include <algorithm>
#include <vector>

namespace gpgmm::d3d12 {

    static constexpr uint64_t kDefaultEvictSizeInBytes = GPGMM_MB_TO_BYTES(50);
    static constexpr float kDefaultMaxPctOfVideoMemoryToBudget = 0.95f;  // 95%
    static constexpr float kDefaultMinPctOfBudgetToReserve = 0.50f;      // 50%
    static constexpr float kMinCurrentUsageOfBudgetReportingThreshold = 0.90f;

    HRESULT CreateResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                   ID3D12Device* pDevice,
                                   IDXGIAdapter3* pAdapter,
                                   IResidencyManager** ppResidencyManagerOut) {
        return ResidencyManager::CreateResidencyManager(descriptor, pDevice, pAdapter,
                                                        ppResidencyManagerOut);
    }

    // static
    HRESULT ResidencyManager::CreateResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                                     ID3D12Device* pDevice,
                                                     IDXGIAdapter3* pAdapter,
                                                     IResidencyManager** ppResidencyManagerOut) {
        GPGMM_RETURN_IF_NULLPTR(pAdapter);
        GPGMM_RETURN_IF_NULLPTR(pDevice);

        std::unique_ptr<Caps> caps;
        {
            Caps* ptr = nullptr;
            GPGMM_RETURN_IF_FAILED(Caps::CreateCaps(pDevice, pAdapter, &ptr), pDevice);
            caps.reset(ptr);
        }

        if ((descriptor.Flags & RESIDENCY_FLAG_DISABLE_UNIFIED_MEMORY) && caps->IsAdapterUMA()) {
            WarnLog(MessageId::kInvalidArgument, true)
                << "RESIDENCY_FLAG_DISABLE_UNIFIED_MEMORY flag was specified but "
                   "did not match the architecture of the adapter.";
        }

        if (descriptor.MaxPctOfVideoMemoryToBudget != 0 && descriptor.MaxBudgetInBytes != 0) {
            ErrorLog(MessageId::kInvalidArgument, true)
                << "Both the OS based memory budget and restricted budget were "
                   "specified but cannot be used at the same time.";
            return E_UNEXPECTED;
        }

        if (descriptor.RecordOptions.Flags != RECORD_FLAGS_NONE) {
            StartupEventTrace(descriptor.RecordOptions.TraceFile,
                              static_cast<TraceEventPhase>(~descriptor.RecordOptions.Flags));

            SetEventMessageLevel(GetMessageSeverity(descriptor.MinRecordLevel));
        }

        SetLogLevel(GetMessageSeverity(descriptor.MinLogLevel));

        std::unique_ptr<ResidencyManager> residencyManager = std::unique_ptr<ResidencyManager>(
            new ResidencyManager(descriptor, pDevice, pAdapter, std::move(caps)));

        // Enable automatic video memory budget updates.
        if (descriptor.Flags & RESIDENCY_FLAG_ALLOW_BACKGROUND_BUDGET_UPDATES) {
            if (FAILED(residencyManager->StartBudgetNotificationUpdates())) {
                WarnLog(residencyManager.get(), MessageId::kBudgetUpdated)
                    << "RESIDENCY_FLAG_ALLOW_BACKGROUND_BUDGET_UPDATES was requested but failed to "
                       "start.";
            }
        }

        // Set the initial video memory limits.
        GPGMM_RETURN_IF_FAILED(residencyManager->UpdateMemorySegments(), pDevice);

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
            WarnLog(residencyManager.get(), MessageId::kBudgetInvalid)
                << "GPU memory segment ("
                << GetMemorySegmentName(DXGI_MEMORY_SEGMENT_GROUP_LOCAL, residencyManager->mIsUMA)
                << ") did not initialize a budget. This means either a restricted budget was not "
                   "used or the first OS budget update hasn't occured.";
            if (!residencyManager->mIsUMA && nonLocalVideoMemorySegmentInfo->Budget == 0) {
                WarnLog(residencyManager.get(), MessageId::kBudgetInvalid)
                    << "GPU memory segment ("
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

        DebugLog(residencyManager.get(), MessageId::kObjectCreated) << "Created residency manager";

        if (ppResidencyManagerOut != nullptr) {
            *ppResidencyManagerOut = residencyManager.release();
        }

        return S_OK;
    }

    ResidencyManager::ResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                       ID3D12Device* pDevice,
                                       IDXGIAdapter3* pAdapter,
                                       std::unique_ptr<Caps> caps)
        : mDevice(pDevice),
          mAdapter(pAdapter),
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
          mFlushEventBuffersOnDestruct(descriptor.RecordOptions.EventScope &
                                       RECORD_SCOPE_PER_INSTANCE),
          mInitialFenceValue(descriptor.InitialFenceValue),
          mIsAlwaysInBudget(descriptor.Flags & RESIDENCY_FLAG_ALWAYS_IN_BUDGET) {
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

    // Increments number of locks on a heap to ensure the heap remains resident.
    HRESULT ResidencyManager::LockHeap(IResidencyHeap* pHeap) {
        GPGMM_RETURN_IF_NULLPTR(pHeap);

        std::lock_guard<std::mutex> lock(mMutex);

        ResidencyHeap* heap = static_cast<ResidencyHeap*>(pHeap);
        ASSERT(heap != nullptr);

        if (!heap->IsInList() && !heap->IsResidencyLocked()) {
            ComPtr<ID3D12Pageable> pageable;
            GPGMM_RETURN_IF_FAILED(heap->QueryInterface(IID_PPV_ARGS(&pageable)), mDevice);
            GPGMM_RETURN_IF_FAILED(
                MakeResident(heap->GetHeapSegment(), heap->GetSize(), 1, pageable.GetAddressOf()),
                mDevice);
            heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_CURRENT);

            // Untracked heaps, created not resident, are not already attributed toward residency
            // usage because they are not in the residency cache.
            mStats.CurrentHeapCount++;
            mStats.CurrentHeapUsage += heap->GetSize();
        }

        // Since we can't evict the heap, it's unnecessary to track the heap in the LRU Cache.
        if (heap->IsInList()) {
            heap->RemoveFromList();

            // Untracked heaps, previously made resident, are not attributed toward residency usage
            // because they will be removed from the residency cache.
            if (heap->mState == RESIDENCY_HEAP_STATUS_CURRENT) {
                mStats.CurrentHeapCount++;
                mStats.CurrentHeapUsage += heap->GetSize();
            }
        }

        heap->AddResidencyLockRef();

        return S_OK;
    }

    // Decrements number of locks on a heap. When the number of locks becomes zero, the heap is
    // inserted into the LRU cache and becomes eligible for eviction.
    HRESULT ResidencyManager::UnlockHeap(IResidencyHeap* pHeap) {
        GPGMM_RETURN_IF_NULLPTR(pHeap);

        std::lock_guard<std::mutex> lock(mMutex);
        ResidencyHeap* heap = static_cast<ResidencyHeap*>(pHeap);
        ASSERT(heap != nullptr);

        // If the heap was never locked, nothing further should be done.
        if (!heap->IsResidencyLocked()) {
            return S_OK;
        }

        if (heap->IsInList()) {
            ErrorLog(this, MessageId::kBadOperation)
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
        GPGMM_RETURN_IF_FAILED(InsertHeapInternal(heap), mDevice);

        // Heaps inserted into the residency cache are already attributed in residency usage.
        mStats.CurrentHeapCount--;
        mStats.CurrentHeapUsage -= heap->GetSize();

        return S_OK;
    }

    HRESULT ResidencyManager::InsertHeap(ResidencyHeap* pHeap) {
        std::lock_guard<std::mutex> lock(mMutex);
        return InsertHeapInternal(pHeap);
    }

    // Inserts a heap at the bottom of the LRU. The passed heap must be resident or scheduled to
    // become resident within the current serial. Failing to call this function when an allocation
    // is implicitly made resident will cause the residency manager to view the allocation as
    // non-resident and call MakeResident - which will make D3D12's internal residency refcount on
    // the allocation out of sync with Dawn.
    HRESULT ResidencyManager::InsertHeapInternal(ResidencyHeap* heap) {
        if (heap == nullptr) {
            return E_INVALIDARG;
        }

        // Heap already exists in the cache.
        if (heap->IsInList()) {
            return E_INVALIDARG;
        }

        LRUCache* cache = GetVideoMemorySegmentCache(heap->GetHeapSegment());
        ASSERT(cache != nullptr);

        heap->InsertAfter(cache->tail());

        ASSERT(heap->IsInList());

        return S_OK;
    }

    DXGI_QUERY_VIDEO_MEMORY_INFO* ResidencyManager::GetVideoMemoryInfo(
        const DXGI_MEMORY_SEGMENT_GROUP& heapSegment) {
        switch (heapSegment) {
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
        const DXGI_MEMORY_SEGMENT_GROUP& heapSegment) {
        switch (heapSegment) {
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
        const DXGI_MEMORY_SEGMENT_GROUP& heapSegment,
        uint64_t availableForReservation,
        uint64_t* pCurrentReservationOut) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResidencyManager.SetVideoMemoryReservation");

        std::lock_guard<std::mutex> lock(mMutex);

        DXGI_QUERY_VIDEO_MEMORY_INFO* videoMemorySegmentInfo = GetVideoMemoryInfo(heapSegment);

        videoMemorySegmentInfo->AvailableForReservation = availableForReservation;

        if (IsBudgetNotificationUpdatesDisabled()) {
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(heapSegment), mDevice);
        }

        if (pCurrentReservationOut != nullptr) {
            *pCurrentReservationOut = videoMemorySegmentInfo->CurrentReservation;
        }

        return S_OK;
    }

    HRESULT ResidencyManager::UpdateMemorySegmentInternal(
        const DXGI_MEMORY_SEGMENT_GROUP& heapSegment) {
        // For UMA adapters, non-local is always zero.
        if (mIsUMA && heapSegment == DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL) {
            return S_OK;
        }

        DXGI_QUERY_VIDEO_MEMORY_INFO queryVideoMemoryInfoOut;
        GPGMM_RETURN_IF_FAILED(
            mAdapter->QueryVideoMemoryInfo(0, heapSegment, &queryVideoMemoryInfoOut), mDevice);

        // The video memory budget provided by QueryVideoMemoryInfo is defined by the operating
        // system, and may be lower than expected in certain scenarios. Under memory pressure, we
        // cap the external reservation to half the available budget, which prevents the external
        // component from consuming a disproportionate share of memory and ensures forward progress.
        DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfo = GetVideoMemoryInfo(heapSegment);

        pVideoMemoryInfo->CurrentReservation = std::min(
            static_cast<uint64_t>(queryVideoMemoryInfoOut.Budget * mMinPctOfBudgetToReserve),
            pVideoMemoryInfo->AvailableForReservation);

        const uint64_t previousUsage = pVideoMemoryInfo->CurrentUsage;
        pVideoMemoryInfo->CurrentUsage =
            queryVideoMemoryInfoOut.CurrentUsage - pVideoMemoryInfo->CurrentReservation;

        if (previousUsage > pVideoMemoryInfo->CurrentUsage &&
            GPGMM_BYTES_TO_MB(previousUsage - pVideoMemoryInfo->CurrentUsage) > 0) {
            DebugLog(this, MessageId::kMemoryUsageUpdated)
                << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory usage went down by "
                << GPGMM_BYTES_TO_MB(previousUsage - pVideoMemoryInfo->CurrentUsage) << " MBs.";
        } else if (previousUsage < pVideoMemoryInfo->CurrentUsage &&
                   GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentUsage - previousUsage) > 0) {
            DebugLog(this, MessageId::kMemoryUsageUpdated)
                << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory usage went up by "
                << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentUsage - previousUsage) << " MBs.";
        } else if (previousUsage < pVideoMemoryInfo->CurrentUsage) {
            DebugLog(this, MessageId::kMemoryUsageUpdated)
                << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory usage went up by "
                << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentUsage) << " MBs.";
        }

        // If we're restricting the budget, leave the budget as is.
        if (!mIsBudgetRestricted) {
            const uint64_t previousBudget = pVideoMemoryInfo->Budget;
            pVideoMemoryInfo->Budget = static_cast<uint64_t>(
                (queryVideoMemoryInfoOut.Budget - pVideoMemoryInfo->CurrentReservation) *
                mMaxPctOfVideoMemoryToBudget);

            if (previousBudget > pVideoMemoryInfo->Budget &&
                GPGMM_BYTES_TO_MB(previousBudget - pVideoMemoryInfo->Budget) > 0) {
                DebugLog(this, MessageId::kMemoryUsageUpdated)
                    << GetMemorySegmentName(heapSegment, mIsUMA)
                    << " GPU memory budget went down by "
                    << GPGMM_BYTES_TO_MB(previousBudget - pVideoMemoryInfo->Budget) << " MBs.";
            } else if (previousBudget < pVideoMemoryInfo->Budget &&
                       GPGMM_BYTES_TO_MB(pVideoMemoryInfo->Budget - previousBudget) > 0) {
                DebugLog(this, MessageId::kMemoryUsageUpdated)
                    << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory budget went up by "
                    << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->Budget - previousBudget) << " MBs.";
            }
        }

        // Ignore when no budget was specified.
        if (pVideoMemoryInfo->Budget > 0 &&
            pVideoMemoryInfo->CurrentUsage > pVideoMemoryInfo->Budget) {
            WarnEvent(this, MessageId::kBudgetExceeded)
                << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory usage exceeds budget: "
                << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentUsage) << " vs "
                << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->Budget) << " MBs.";
        } else {
            const float currentUsageOfBudget =
                SafeDivide(pVideoMemoryInfo->CurrentUsage, pVideoMemoryInfo->Budget);
            if (pVideoMemoryInfo->Budget > 0 &&
                currentUsageOfBudget > kMinCurrentUsageOfBudgetReportingThreshold) {
                EventMessage message = WarnEvent(this, MessageId::kBudgetExceeded);
                message << GetMemorySegmentName(heapSegment, mIsUMA)
                        << " GPU memory usage is above budget threshold: "
                        << uint64_t(currentUsageOfBudget * 100) << "% vs "
                        << uint64_t(kMinCurrentUsageOfBudgetReportingThreshold * 100) << "%";

                // Check if even evicting resident heaps would get us back below the budget or not.
                // Otherwise, warn the developer that E_OUTOFMEMORY is likely unavoidable.
                if (pVideoMemoryInfo->CurrentUsage > mStats.CurrentHeapUsage &&
                    (pVideoMemoryInfo->CurrentUsage - mStats.CurrentHeapUsage >
                     pVideoMemoryInfo->Budget)) {
                    message
                        << "There is not enough memory to page-out to get below the budget. This "
                           "likely means there are more external than internal heaps that cannot "
                           "be "
                           "evicted because they are unmanaged by GPGMM. Consider using "
                           "CreateResidencyHeap "
                           "to import them: "
                        << GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentUsage) << " vs "
                        << GPGMM_BYTES_TO_MB(mStats.CurrentHeapUsage) << " MBs.";
                }
            }
        }

        // Not all segments could be used.
        GPGMM_TRACE_EVENT_METRIC(
            ToString(GetMemorySegmentName(heapSegment, mIsUMA), " GPU memory usage (%)").c_str(),
            (pVideoMemoryInfo->CurrentUsage > pVideoMemoryInfo->Budget)
                ? 100
                : SafeDivide(pVideoMemoryInfo->CurrentUsage, pVideoMemoryInfo->Budget) * 100);

        // Reservations are optional.
        GPGMM_TRACE_EVENT_METRIC(
            ToString(GetMemorySegmentName(heapSegment, mIsUMA), " GPU memory reserved (MB)")
                .c_str(),
            GPGMM_BYTES_TO_MB(pVideoMemoryInfo->CurrentReservation));

        return S_OK;
    }

    HRESULT ResidencyManager::UpdateMemorySegments() {
        std::lock_guard<std::mutex> lock(mMutex);
        GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(DXGI_MEMORY_SEGMENT_GROUP_LOCAL),
                               mDevice);
        GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL),
                               mDevice);
        return S_OK;
    }

    HRESULT ResidencyManager::QueryVideoMemoryInfo(
        const DXGI_MEMORY_SEGMENT_GROUP& heapSegment,
        DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfoOut) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (IsBudgetNotificationUpdatesDisabled()) {
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(heapSegment), mDevice);
        }

        if (pVideoMemoryInfoOut != nullptr) {
            *pVideoMemoryInfoOut = *GetVideoMemoryInfo(heapSegment);
        }

        return S_OK;
    }

    // Evicts |evictSizeInBytes| bytes of memory in |heapSegment| and returns the number of
    // bytes evicted.
    HRESULT ResidencyManager::EvictInternal(uint64_t bytesToEvict,
                                            const DXGI_MEMORY_SEGMENT_GROUP& heapSegment,
                                            uint64_t* bytesEvictedOut) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault, "ResidencyManager.Evict");

        DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfo = GetVideoMemoryInfo(heapSegment);
        if (IsBudgetNotificationUpdatesDisabled()) {
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(heapSegment), mDevice);
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

        GPGMM_RETURN_IF_FAILED(EnsureResidencyFenceExists(), mDevice);

        uint64_t bytesEvicted = 0;
        while (bytesEvicted < bytesNeededToBeUnderBudget) {
            // If the cache is empty, allow execution to continue. Note that fully
            // emptying the cache is undesirable, because it can mean either 1) the cache is not
            // accurately accounting for GPU allocations, or 2) an external component is
            // using all of the budget and is starving us, which will cause thrash.
            LRUCache* cache = GetVideoMemorySegmentCache(heapSegment);
            ASSERT(cache != nullptr);

            if (cache->empty()) {
                break;
            }

            ResidencyHeap* heap = cache->head()->value();
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
            GPGMM_RETURN_IF_FAILED(mResidencyFence->WaitFor(lastUsedFenceValue), mDevice);

            heap->RemoveFromList();
            heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_PENDING);

            bytesEvicted += heap->GetSize();

            ComPtr<ID3D12Pageable> pageable;
            GPGMM_RETURN_IF_FAILED(heap->QueryInterface(IID_PPV_ARGS(&pageable)), mDevice);

            objectsToEvict.push_back(pageable.Get());
        }

        if (objectsToEvict.size() > 0) {
            GPGMM_TRACE_EVENT_METRIC("GPU memory page-out (MB)", GPGMM_BYTES_TO_MB(bytesEvicted));

            const uint32_t objectEvictCount = static_cast<uint32_t>(objectsToEvict.size());
            GPGMM_RETURN_IF_FAILED(mDevice->Evict(objectEvictCount, objectsToEvict.data()),
                                   mDevice);

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
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResidencyManager.ExecuteCommandLists");

        std::lock_guard<std::mutex> lock(mMutex);

        if (count == 0) {
            ErrorLog(this, MessageId::kInvalidArgument)
                << "ExecuteCommandLists is required to have at-least one residency "
                   "list to be called.";
            return E_INVALIDARG;
        }

        // TODO: support multiple command lists.
        if (count > 1) {
            ErrorLog(this, MessageId::kInvalidArgument)
                << "ExecuteCommandLists does not support multiple residency lists at this time. "
                   "Please call ExecuteCommandLists per residency list as a workaround, if needed.";
            return E_NOTIMPL;
        }

        GPGMM_RETURN_IF_FAILED(EnsureResidencyFenceExists(), mDevice);

        ResidencyList* residencyList = static_cast<ResidencyList*>(ppResidencyLists[0]);

        std::vector<ID3D12Pageable*> localHeapsToMakeResident;
        std::vector<ID3D12Pageable*> nonLocalHeapsToMakeResident;
        uint64_t localSizeToMakeResident = 0;
        uint64_t nonLocalSizeToMakeResident = 0;

        std::vector<ResidencyHeap*> heapsToMakeResident;
        for (ResidencyHeap* heap : *residencyList) {
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
                GPGMM_RETURN_IF_FAILED(heap->QueryInterface(IID_PPV_ARGS(&pageable)), mDevice);

                if (heap->GetHeapSegment() == DXGI_MEMORY_SEGMENT_GROUP_LOCAL) {
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
            if (heap->GetInfo().Status == RESIDENCY_HEAP_STATUS_UNKNOWN) {
                DebugLog(this, MessageId::kBadOperation)
                    << "Residency state could not be determined for the heap (Heap="
                    << ToHexStr(heap)
                    << "). This likely means the developer was attempting to make a "
                       "non-resource heap resident without calling lock/unlock first.";
            }
        }

        if (localSizeToMakeResident > 0) {
            const uint32_t numberOfObjectsToMakeResident =
                static_cast<uint32_t>(localHeapsToMakeResident.size());
            GPGMM_RETURN_IF_FAILED(
                MakeResident(DXGI_MEMORY_SEGMENT_GROUP_LOCAL, localSizeToMakeResident,
                             numberOfObjectsToMakeResident, localHeapsToMakeResident.data()),
                mDevice);
        } else if (nonLocalSizeToMakeResident > 0) {
            const uint32_t numberOfObjectsToMakeResident =
                static_cast<uint32_t>(nonLocalHeapsToMakeResident.size());
            GPGMM_RETURN_IF_FAILED(
                MakeResident(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL, nonLocalSizeToMakeResident,
                             numberOfObjectsToMakeResident, nonLocalHeapsToMakeResident.data()),
                mDevice);
        }

        // Once MakeResident succeeds, we must assume the heaps are resident since D3D12 provides
        // no way of knowing for certain.
        for (ResidencyHeap* heap : heapsToMakeResident) {
            heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_CURRENT);
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
            GPGMM_RETURN_IF_FAILED(mResidencyFence->Signal(pQueue), mDevice);
        }

        // Keep video memory segments up-to-date. This must always happen because if the budget
        // never changes (ie. not manually updated or through budget change events), the
        // residency manager wouldn't know what to page in or out.
        if (IsBudgetNotificationUpdatesDisabled()) {
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(DXGI_MEMORY_SEGMENT_GROUP_LOCAL),
                                   mDevice);
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL),
                                   mDevice);
        }

        GPGMM_TRACE_EVENT_OBJECT_CALL("ResidencyManager.ExecuteCommandLists",
                                      (EXECUTE_COMMAND_LISTS_DESC{ppResidencyLists, count}));

        return S_OK;
    }

    HRESULT ResidencyManager::MakeResident(const DXGI_MEMORY_SEGMENT_GROUP heapSegment,
                                           uint64_t sizeToMakeResident,
                                           uint32_t numberOfObjectsToMakeResident,
                                           ID3D12Pageable** allocations) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault, "ResidencyManager.MakeResident");

        GPGMM_RETURN_IF_FAILED(EvictInternal(sizeToMakeResident, heapSegment, nullptr), mDevice);

        DebugEvent(this, MessageId::kBudgetExceeded)
            << "GPU page-in. Number of allocations: " << numberOfObjectsToMakeResident << " ("
            << sizeToMakeResident << " bytes).";

        // Decrease the overhead from using MakeResident, a synchronous call, by calling the
        // asynchronous MakeResident, called EnqueueMakeResident, instead first. Should
        // EnqueueMakeResident fail, fall-back to using synchronous MakeResident since we may be
        // able to continue after calling Evict again.
        ComPtr<ID3D12Device3> device3;
        if (SUCCEEDED(mDevice->QueryInterface(IID_PPV_ARGS(&device3)))) {
            GPGMM_RETURN_IF_FAILED(EnsureResidencyFenceExists(), mDevice);
            GPGMM_RETURN_IF_SUCCEEDED(device3->EnqueueMakeResident(
                (mIsAlwaysInBudget) ? D3D12_RESIDENCY_FLAG_DENY_OVERBUDGET
                                    : D3D12_RESIDENCY_FLAG_NONE,
                numberOfObjectsToMakeResident, allocations, mResidencyFence->GetFence(),
                mResidencyFence->GetCurrentFence()));
        }

        // A MakeResident call can fail if there's not enough available memory. This
        // could occur when there's significant fragmentation or if the allocation size
        // estimates are incorrect. We may be able to continue execution by evicting some
        // more memory and calling MakeResident again.
        while (FAILED(mDevice->MakeResident(numberOfObjectsToMakeResident, allocations))) {
            // If nothing can be evicted after MakeResident has failed, we cannot continue
            // execution and must throw a fatal error.
            uint64_t evictedSizeInBytes = 0;
            GPGMM_RETURN_IF_FAILED(
                EvictInternal(mEvictSizeInBytes, heapSegment, &evictedSizeInBytes), mDevice);
            if (evictedSizeInBytes == 0) {
                ErrorLog(this, MessageId::kBudgetInvalid)
                    << "Unable to evict enough heaps to stay within budget. This "
                       "usually occurs when there is not enough available memory. "
                       "Please reduce consumption by checking allocation sizes and "
                       "residency usage.";
                return (mIsAlwaysInBudget) ? E_OUTOFMEMORY : S_FALSE;
            }
        }

        return S_OK;
    }

    HRESULT ResidencyManager::QueryStats(RESIDENCY_MANAGER_STATS* pResidencyManagerStats) {
        std::lock_guard<std::mutex> lock(mMutex);
        return QueryStatsInternal(pResidencyManagerStats);
    }

    HRESULT ResidencyManager::QueryStatsInternal(RESIDENCY_MANAGER_STATS* pResidencyManagerStats) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault, "ResidencyManager.GetStats");

        // Heaps inserted into the residency cache are not resident until MakeResident() is called
        // on them. This occurs if the heap was created resident, heap gets locked, or call to
        // ExecuteCommandLists().

        // Locked heaps are not stored in the residency cache, so usage must be tracked by the
        // residency manager on Lock/Unlock then added here to get the sum.
        RESIDENCY_MANAGER_STATS result = mStats;

        for (const auto& entry : mLocalVideoMemorySegment.cache) {
            if (entry.value()->GetInfo().Status == RESIDENCY_HEAP_STATUS_CURRENT) {
                result.CurrentHeapUsage += entry.value()->GetSize();
                result.CurrentHeapCount++;
            }
        }

        for (const auto& entry : mNonLocalVideoMemorySegment.cache) {
            if (entry.value()->GetInfo().Status == RESIDENCY_HEAP_STATUS_CURRENT) {
                result.CurrentHeapUsage += entry.value()->GetSize();
                result.CurrentHeapCount++;
            }
        }

        GPGMM_TRACE_EVENT_METRIC("GPU currently resident (MB)",
                                 GPGMM_BYTES_TO_MB(result.CurrentHeapUsage));

        if (pResidencyManagerStats != nullptr) {
            *pResidencyManagerStats = result;
        } else {
            return S_FALSE;
        }

        return S_OK;
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
        return (mBudgetNotificationUpdateEvent == nullptr) ||
               FAILED(mBudgetNotificationUpdateEvent->GetLastError());
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

        DebugLog(this) << GetMemorySegmentName(segmentGroup, IsUMA()) << " GPU memory segment:";
        DebugLog(this) << "\tBudget: " << GPGMM_BYTES_TO_MB(info->Budget) << " MBs ("
                       << GPGMM_BYTES_TO_MB(info->CurrentUsage) << " used).";

        if (info->CurrentReservation == 0) {
            DebugLog(this) << "\tReserved: " << GPGMM_BYTES_TO_MB(info->CurrentReservation)
                           << " MBs (" << GPGMM_BYTES_TO_MB(info->AvailableForReservation)
                           << " available).";
        }
    }

    HRESULT ResidencyManager::SetResidencyStatus(IResidencyHeap* pHeap,
                                                 const RESIDENCY_HEAP_STATUS& state) {
        GPGMM_RETURN_IF_NULLPTR(pHeap);

        ResidencyHeap* heap = static_cast<ResidencyHeap*>(pHeap);
        if (heap->GetInfo().IsLocked) {
            ErrorLog(this, MessageId::kBadOperation)
                << "Heap residency cannot be updated because it was locked. "
                   "Please unlock the heap before updating the state.";
            return E_FAIL;
        }

        const RESIDENCY_HEAP_STATUS oldState = heap->GetInfo().Status;
        if (state == RESIDENCY_HEAP_STATUS_UNKNOWN && oldState != RESIDENCY_HEAP_STATUS_UNKNOWN) {
            ErrorLog(this, MessageId::kBadOperation)
                << "Heap residency cannot be unknown when previously known by the "
                   "residency manager. "
                   "Check the status before updating the state.";
            return E_FAIL;
        }

        heap->SetResidencyStatus(state);
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
        GPGMM_RETURN_IF_FAILED(Fence::CreateFence(mDevice, mInitialFenceValue, &fencePtr), mDevice);
        mResidencyFence.reset(fencePtr);
        return S_OK;
    }

    LPCWSTR ResidencyManager::GetDebugName() const {
        return DebugObject::GetDebugName();
    }

    HRESULT ResidencyManager::SetDebugName(LPCWSTR Name) {
        return DebugObject::SetDebugNameImpl(Name);
    }

}  // namespace gpgmm::d3d12
