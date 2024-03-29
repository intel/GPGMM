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
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/BudgetUpdateD3D12.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/EventMessageD3D12.h"
#include "gpgmm/d3d12/FenceD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/LogD3D12.h"
#include "gpgmm/d3d12/ResidencyHeapD3D12.h"
#include "gpgmm/d3d12/ResidencyListD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerDXGI.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/Math.h"

#include <algorithm>
#include <vector>

namespace gpgmm::d3d12 {

    static constexpr uint64_t kDefaultEvictSizeInBytes = GPGMM_MB_TO_BYTES(50);
    static constexpr float kDefaultMaxPctOfMemoryToBudget = 0.95f;       // 95%
    static constexpr float kDefaultMinPctOfBudgetToReserve = 0.50f;      // 50%
    static constexpr float kMinCurrentUsageOfBudgetReportingThreshold = 0.90f;

    HRESULT CreateResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                   ID3D12Device* pDevice,
                                   IUnknown* pAdapter,
                                   IResidencyManager** ppResidencyManagerOut) {
        return ResidencyManager::CreateResidencyManager(descriptor, pDevice, pAdapter,
                                                        ppResidencyManagerOut);
    }

    // static
    HRESULT ResidencyManager::CreateResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                                     ID3D12Device* pDevice,
                                                     IUnknown* pAdapter,
                                                     IResidencyManager** ppResidencyManagerOut) {
        GPGMM_RETURN_IF_NULL(pAdapter);
        GPGMM_RETURN_IF_NULL(pDevice);

        std::unique_ptr<Caps> caps;
        {
            Caps* ptr = nullptr;
            GPGMM_RETURN_IF_FAILED(Caps::CreateCaps(pDevice, pAdapter, &ptr));
            caps.reset(ptr);
        }

        if ((descriptor.Flags & RESIDENCY_MANAGER_FLAG_NEVER_USE_UNIFIED_MEMORY) &&
            caps->IsAdapterUMA()) {
            WarnLog(MessageId::kUnknown)
                << "RESIDENCY_MANAGER_FLAG_NEVER_USE_UNIFIED_MEMORY flag was specified but "
                   "did not match the architecture of the adapter.";
        }

        if (descriptor.MaxPctOfMemoryToBudget != 0 && descriptor.MaxBudgetInBytes != 0) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Both the OS based memory budget and restricted budget were "
                   "specified but cannot be used at the same time.";
            return GetErrorResult(ErrorCode::kInvalidArgument);
        }

        if (descriptor.RecordOptions.Flags != RECORD_FLAG_NONE) {
            StartupEventTrace(descriptor.RecordOptions.TraceFile,
                              static_cast<TraceEventPhase>(~descriptor.RecordOptions.Flags));

            SetEventMessageLevel(GetMessageSeverity(descriptor.MinRecordLevel));
        }

        SetLogLevel(GetMessageSeverity(descriptor.MinLogLevel));

        std::unique_ptr<ResidencyManager> residencyManager;
        ComPtr<IDXGIAdapter3> dxgiAdapter3;
        if (SUCCEEDED(pAdapter->QueryInterface(IID_PPV_ARGS(&dxgiAdapter3)))) {
            residencyManager = std::make_unique<ResidencyManagerDXGI>(
                descriptor, pDevice, dxgiAdapter3.Get(), std::move(caps));
        } else {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Residency management is not supported for this adapter.";
            return E_NOINTERFACE;
        }

        // Enable automatic memory budget updates.
        if (descriptor.Flags & RESIDENCY_MANAGER_FLAG_ALLOW_BACKGROUND_BUDGET_UPDATES) {
            if (FAILED(residencyManager->StartBudgetNotificationUpdates())) {
                WarnLog(MessageId::kBudgetUpdated, residencyManager.get())
                    << "RESIDENCY_MANAGER_FLAG_ALLOW_BACKGROUND_BUDGET_UPDATES was requested but "
                       "failed to start.";
            }
        }

        // Set the initial memory limits.
        GPGMM_RETURN_IF_FAILED(residencyManager->UpdateMemorySegments());

        RESIDENCY_MEMORY_INFO* localMemorySegmentInfo =
            residencyManager->GetMemoryInfo(RESIDENCY_HEAP_SEGMENT_LOCAL);

        RESIDENCY_MEMORY_INFO* nonLocalMemorySegmentInfo =
            residencyManager->GetMemoryInfo(RESIDENCY_HEAP_SEGMENT_NON_LOCAL);

        // D3D12 has non-zero memory usage even before any resources have been created, and this
        // value can vary by OS enviroment. By adding this in addition to the artificial budget
        // limit, we can create a predictable and reproducible budget.
        if (descriptor.MaxBudgetInBytes > 0) {
            localMemorySegmentInfo->Budget =
                localMemorySegmentInfo->CurrentUsage + descriptor.MaxBudgetInBytes;
            if (!residencyManager->mIsUMA) {
                nonLocalMemorySegmentInfo->Budget =
                    nonLocalMemorySegmentInfo->CurrentUsage + descriptor.MaxBudgetInBytes;
            }
        }

        // Emit a warning if the budget was initialized to zero.
        // This means nothing will be ever evicted, which will lead to device lost.
        if (localMemorySegmentInfo->Budget == 0) {
            WarnLog(MessageId::kBudgetUpdated, residencyManager.get())
                << "GPU memory segment ("
                << GetMemorySegmentName(RESIDENCY_HEAP_SEGMENT_LOCAL, residencyManager->mIsUMA)
                << ") did not initialize a budget. This means either a restricted budget was not "
                   "used or the first OS budget update hasn't occured.";
            if (!residencyManager->mIsUMA && nonLocalMemorySegmentInfo->Budget == 0) {
                WarnLog(MessageId::kBudgetUpdated, residencyManager.get())
                    << "GPU memory segment ("
                    << GetMemorySegmentName(RESIDENCY_HEAP_SEGMENT_NON_LOCAL,
                                            residencyManager->mIsUMA)
                    << ") did not initialize a budget. This means either a "
                       "restricted budget was not "
                       "used or the first OS budget update hasn't occured.";
            }
        }

        // Dump out the initialized memory segment status.
        residencyManager->ReportSegmentInfoForTesting(RESIDENCY_HEAP_SEGMENT_LOCAL);
        if (!residencyManager->mIsUMA) {
            residencyManager->ReportSegmentInfoForTesting(RESIDENCY_HEAP_SEGMENT_NON_LOCAL);
        }

        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(residencyManager.get(), descriptor);

        DebugLog(MessageId::kObjectCreated, residencyManager.get()) << "Created residency manager";

        if (ppResidencyManagerOut != nullptr) {
            *ppResidencyManagerOut = residencyManager.release();
        }

        return S_OK;
    }

    ResidencyManager::ResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                       ID3D12Device* pDevice,
                                       std::unique_ptr<Caps> caps)
        : mDevice(pDevice),
          mMaxPctOfMemoryToBudget(descriptor.MaxPctOfMemoryToBudget == 0
                                      ? kDefaultMaxPctOfMemoryToBudget
                                      : descriptor.MaxPctOfMemoryToBudget),
          mMinPctOfBudgetToReserve(descriptor.MinPctOfBudgetToReserve == 0
                                       ? kDefaultMinPctOfBudgetToReserve
                                       : descriptor.MinPctOfBudgetToReserve),
          mIsBudgetRestricted(descriptor.MaxBudgetInBytes > 0),
          mEvictSizeInBytes(descriptor.EvictSizeInBytes == 0 ? kDefaultEvictSizeInBytes
                                                             : descriptor.EvictSizeInBytes),
          mIsUMA(caps->IsAdapterUMA() &&
                 !(descriptor.Flags & RESIDENCY_MANAGER_FLAG_NEVER_USE_UNIFIED_MEMORY)),
          mFlushEventBuffersOnDestruct(descriptor.RecordOptions.EventScope &
                                       RECORD_SCOPE_PER_INSTANCE),
          mInitialFenceValue(descriptor.InitialFenceValue),
          mIsAlwaysInBudget(descriptor.Flags & RESIDENCY_MANAGER_FLAG_ALWAYS_IN_BUDGET) {
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);
        ASSERT(mDevice != nullptr);
    }

    void ResidencyManager::DeleteThis() {
        StopBudgetNotificationUpdates();
        Unknown::DeleteThis();
    }

    ResidencyManager::~ResidencyManager() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
        if (mFlushEventBuffersOnDestruct) {
            FlushEventTraceToDisk();
        }
    }

    // Increments number of locks on a heap to ensure the heap remains resident.
    HRESULT ResidencyManager::LockHeap(ResidencyHeap* heap) {
        GPGMM_RETURN_IF_NULL(heap);

        std::lock_guard<std::mutex> lock(mMutex);
        if (!heap->IsInList() && !heap->IsResidencyLocked()) {
            ComPtr<ID3D12Pageable> pageable;
            GPGMM_RETURN_IF_FAILED(heap->QueryInterface(IID_PPV_ARGS(&pageable)), mDevice);
            GPGMM_RETURN_IF_FAILED(MakeResident(heap->GetMemorySegment(), heap->GetSize(), 1,
                                                pageable.GetAddressOf()));
            heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_RESIDENT);

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
            if (heap->GetInfo().Status == RESIDENCY_HEAP_STATUS_RESIDENT) {
                mStats.CurrentHeapCount++;
                mStats.CurrentHeapUsage += heap->GetSize();
            }
        }

        heap->IncrementResidencyLockCount();

        return S_OK;
    }

    // Decrements number of locks on a heap. When the number of locks becomes zero, the heap is
    // inserted into the LRU cache and becomes eligible for eviction.
    HRESULT ResidencyManager::UnlockHeap(ResidencyHeap* heap) {
        GPGMM_RETURN_IF_NULL(heap);

        std::lock_guard<std::mutex> lock(mMutex);

        // If the heap was never locked, nothing further should be done.
        if (!heap->IsResidencyLocked()) {
            return S_OK;
        }

        if (heap->IsInList()) {
            ErrorLog(ErrorCode::kBadOperation, this)
                << "Heap was never being tracked for residency. This usually occurs when a "
                   "non-resource heap was created by the developer and never made resident at "
                   "creation or failure to call LockHeap beforehand.";
            return GetErrorResult(ErrorCode::kBadOperation);
        }

        heap->DecrementResidencyLockCount();

        // If another lock still exists on the heap, nothing further should be done.
        if (heap->IsResidencyLocked()) {
            return S_FALSE;
        }

        // When all locks have been removed, the resource remains resident and becomes tracked in
        // the corresponding LRU.
        GPGMM_RETURN_IF_FAILED(InsertHeapInternal(heap));

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

        LRUCache* cache = GetMemorySegmentCache(heap->GetMemorySegment());
        ASSERT(cache != nullptr);

        heap->InsertAfter(cache->tail());

        ASSERT(heap->IsInList());

        return S_OK;
    }

    RESIDENCY_MEMORY_INFO* ResidencyManager::GetMemoryInfo(
        const RESIDENCY_HEAP_SEGMENT& heapSegment) {
        switch (heapSegment) {
            case RESIDENCY_HEAP_SEGMENT_LOCAL:
                return &mLocalMemorySegment.Info;
            case RESIDENCY_HEAP_SEGMENT_NON_LOCAL:
                return &mNonLocalMemorySegment.Info;
            default:
                UNREACHABLE();
                return nullptr;
        }
    }

    ResidencyManager::LRUCache* ResidencyManager::GetMemorySegmentCache(
        const RESIDENCY_HEAP_SEGMENT& heapSegment) {
        switch (heapSegment) {
            case RESIDENCY_HEAP_SEGMENT_LOCAL:
                return &mLocalMemorySegment.cache;
            case RESIDENCY_HEAP_SEGMENT_NON_LOCAL:
                return &mNonLocalMemorySegment.cache;
            default:
                UNREACHABLE();
                return nullptr;
        }
    }

    // Sends the minimum required physical memory for an application, to this residency
    // manager. Returns the amount of memory reserved, which may be less then the |reservation| when
    // under memory pressure.
    HRESULT ResidencyManager::SetMemoryReservation(const RESIDENCY_HEAP_SEGMENT& heapSegment,
                                                   uint64_t availableForReservation,
                                                   uint64_t* pCurrentReservationOut) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResidencyManager.SetMemoryReservation");

        std::lock_guard<std::mutex> lock(mMutex);

        RESIDENCY_MEMORY_INFO* memorySegmentInfo = GetMemoryInfo(heapSegment);
        memorySegmentInfo->AvailableForReservation = availableForReservation;

        if (IsBudgetNotificationUpdatesDisabled()) {
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(heapSegment));
        }

        if (pCurrentReservationOut != nullptr) {
            *pCurrentReservationOut = memorySegmentInfo->CurrentReservation;
        }

        return S_OK;
    }

    HRESULT ResidencyManager::UpdateMemorySegmentInternal(
        const RESIDENCY_HEAP_SEGMENT& heapSegment) {
        // For UMA adapters, non-local is always zero.
        if (mIsUMA && heapSegment == RESIDENCY_HEAP_SEGMENT_NON_LOCAL) {
            return S_OK;
        }

        RESIDENCY_MEMORY_INFO queryVideoMemoryInfoOut = {};
        GPGMM_RETURN_IF_FAILED(QueryMemoryInfoImpl(heapSegment, &queryVideoMemoryInfoOut));

        // The memory budget provided by QueryMemoryInfo is defined by the operating
        // system, and may be lower than expected in certain scenarios. Under memory pressure, we
        // cap the external reservation to half the available budget, which prevents the external
        // component from consuming a disproportionate share of memory and ensures forward progress.
        RESIDENCY_MEMORY_INFO* memorySegmentInfo = GetMemoryInfo(heapSegment);

        memorySegmentInfo->CurrentReservation = std::min(
            static_cast<uint64_t>(queryVideoMemoryInfoOut.Budget * mMinPctOfBudgetToReserve),
            memorySegmentInfo->AvailableForReservation);

        const uint64_t previousUsage = memorySegmentInfo->CurrentUsage;
        memorySegmentInfo->CurrentUsage =
            queryVideoMemoryInfoOut.CurrentUsage - memorySegmentInfo->CurrentReservation;

        if (previousUsage > memorySegmentInfo->CurrentUsage &&
            GPGMM_BYTES_TO_MB(previousUsage - memorySegmentInfo->CurrentUsage) > 0) {
            DebugLog(MessageId::kMemoryUsageUpdated, this)
                << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory usage went down by "
                << GetBytesToSizeInUnits(previousUsage - memorySegmentInfo->CurrentUsage) << ".";
        } else if (previousUsage < memorySegmentInfo->CurrentUsage &&
                   GPGMM_BYTES_TO_MB(memorySegmentInfo->CurrentUsage - previousUsage) > 0) {
            DebugLog(MessageId::kMemoryUsageUpdated, this)
                << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory usage went up by "
                << GetBytesToSizeInUnits(memorySegmentInfo->CurrentUsage - previousUsage) << ".";
        } else if (previousUsage < memorySegmentInfo->CurrentUsage) {
            DebugLog(MessageId::kMemoryUsageUpdated, this)
                << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory usage went up by "
                << GetBytesToSizeInUnits(memorySegmentInfo->CurrentUsage) << ".";
        }

        // If we're restricting the budget, leave the budget as is.
        if (!mIsBudgetRestricted) {
            const uint64_t previousBudget = memorySegmentInfo->Budget;
            memorySegmentInfo->Budget = static_cast<uint64_t>(
                (queryVideoMemoryInfoOut.Budget - memorySegmentInfo->CurrentReservation) *
                mMaxPctOfMemoryToBudget);

            if (previousBudget > memorySegmentInfo->Budget &&
                GPGMM_BYTES_TO_MB(previousBudget - memorySegmentInfo->Budget) > 0) {
                DebugLog(MessageId::kMemoryUsageUpdated, this)
                    << GetMemorySegmentName(heapSegment, mIsUMA)
                    << " GPU memory budget went down by "
                    << GetBytesToSizeInUnits(previousBudget - memorySegmentInfo->Budget) << ".";
            } else if (previousBudget < memorySegmentInfo->Budget &&
                       GPGMM_BYTES_TO_MB(memorySegmentInfo->Budget - previousBudget) > 0) {
                DebugLog(MessageId::kMemoryUsageUpdated, this)
                    << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory budget went up by "
                    << GetBytesToSizeInUnits(memorySegmentInfo->Budget - previousBudget) << ".";
            }
        }

        // Ignore when no budget was specified.
        if (memorySegmentInfo->Budget > 0 &&
            memorySegmentInfo->CurrentUsage > memorySegmentInfo->Budget) {
            WarnEvent(MessageId::kBudgetExceeded, this)
                << GetMemorySegmentName(heapSegment, mIsUMA) << " GPU memory usage exceeds budget: "
                << GetBytesToSizeInUnits(memorySegmentInfo->CurrentUsage) << " vs "
                << GetBytesToSizeInUnits(memorySegmentInfo->Budget) << ".";
        } else {
            const float currentUsageOfBudget =
                SafeDivide(memorySegmentInfo->CurrentUsage, memorySegmentInfo->Budget);
            if (memorySegmentInfo->Budget > 0 &&
                currentUsageOfBudget > kMinCurrentUsageOfBudgetReportingThreshold) {
                EventMessage message = WarnEvent(MessageId::kBudgetExceeded, this);
                message << GetMemorySegmentName(heapSegment, mIsUMA)
                        << " GPU memory usage is above budget threshold: "
                        << uint64_t(currentUsageOfBudget * 100) << "% vs "
                        << uint64_t(kMinCurrentUsageOfBudgetReportingThreshold * 100) << "%";

                // Check if even evicting resident heaps would get us back below the budget or not.
                // Otherwise, warn the developer that E_OUTOFMEMORY is likely unavoidable.
                if (memorySegmentInfo->CurrentUsage > mStats.CurrentHeapUsage &&
                    (memorySegmentInfo->CurrentUsage - mStats.CurrentHeapUsage >
                     memorySegmentInfo->Budget)) {
                    message
                        << "There is not enough memory to page-out to get below the budget. This "
                           "likely means there are more external than internal heaps that cannot "
                           "be "
                           "evicted because they are unmanaged by GPGMM. Consider using "
                           "CreateResidencyHeap "
                           "to import them: "
                        << GetBytesToSizeInUnits(memorySegmentInfo->CurrentUsage) << " vs "
                        << GetBytesToSizeInUnits(mStats.CurrentHeapUsage) << ".";
                }
            }
        }

        // Not all segments could be used.
        GPGMM_TRACE_EVENT_METRIC(
            ToString(GetMemorySegmentName(heapSegment, mIsUMA), " GPU memory usage (%)").c_str(),
            (memorySegmentInfo->CurrentUsage > memorySegmentInfo->Budget)
                ? 100
                : SafeDivide(memorySegmentInfo->CurrentUsage, memorySegmentInfo->Budget) * 100);

        // Reservations are optional.
        GPGMM_TRACE_EVENT_METRIC(
            ToString(GetMemorySegmentName(heapSegment, mIsUMA), " GPU memory reserved (MB)")
                .c_str(),
            GPGMM_BYTES_TO_MB(memorySegmentInfo->CurrentReservation));

        return S_OK;
    }

    HRESULT ResidencyManager::UpdateMemorySegments() {
        std::lock_guard<std::mutex> lock(mMutex);
        GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(RESIDENCY_HEAP_SEGMENT_LOCAL));
        GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(RESIDENCY_HEAP_SEGMENT_NON_LOCAL));
        return S_OK;
    }

    HRESULT ResidencyManager::QueryMemoryInfo(const RESIDENCY_HEAP_SEGMENT& heapSegment,
                                              RESIDENCY_MEMORY_INFO* pMemoryInfoOut) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (IsBudgetNotificationUpdatesDisabled()) {
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(heapSegment));
        }

        if (pMemoryInfoOut != nullptr) {
            *pMemoryInfoOut = *GetMemoryInfo(heapSegment);
        }

        return S_OK;
    }

    // Evicts |evictSizeInBytes| bytes of memory in |heapSegment| and returns the number of
    // bytes evicted.
    HRESULT ResidencyManager::EvictInternal(uint64_t bytesToEvict,
                                            const RESIDENCY_HEAP_SEGMENT& heapSegment,
                                            uint64_t* bytesEvictedOut) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault, "ResidencyManager.Evict");

        RESIDENCY_MEMORY_INFO* memorySegmentInfo = GetMemoryInfo(heapSegment);
        if (IsBudgetNotificationUpdatesDisabled()) {
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(heapSegment));
        }

        // If a budget wasn't provided, it not possible to evict. This is because either the budget
        // update event has not happened yet or was invalid.
        if (memorySegmentInfo->Budget == 0) {
            WarnEvent(MessageId::kBudgetExceeded, this)
                << "GPU memory segment ("
                << GetMemorySegmentName(RESIDENCY_HEAP_SEGMENT_NON_LOCAL, IsUMA())
                << ") was unable to evict memory because a budget was not specified.";
            return S_FALSE;
        }

        const uint64_t currentUsageAfterEvict = bytesToEvict + memorySegmentInfo->CurrentUsage;

        // Return if we will remain under budget after evict.
        if (currentUsageAfterEvict < memorySegmentInfo->Budget) {
            return S_OK;
        }

        // Any time we need to make something resident, we must check that we have enough free
        // memory to make the new object resident while also staying within budget. If there isn't
        // enough memory, we should evict until there is.
        std::vector<ID3D12Pageable*> objectsToEvict;
        const uint64_t bytesNeededToBeUnderBudget =
            currentUsageAfterEvict - memorySegmentInfo->Budget;

        // Return if nothing needs to be evicted to stay within budget.
        if (bytesNeededToBeUnderBudget == 0) {
            return S_OK;
        }

        GPGMM_RETURN_IF_FAILED(EnsureResidencyFenceExists());

        uint64_t bytesEvicted = 0;
        while (bytesEvicted < bytesNeededToBeUnderBudget) {
            // If the cache is empty, allow execution to continue. Note that fully
            // emptying the cache is undesirable, because it can mean either 1) the cache is not
            // accurately accounting for GPU allocations, or 2) an external component is
            // using all of the budget and is starving us, which will cause thrash.
            LRUCache* cache = GetMemorySegmentCache(heapSegment);
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
            GPGMM_RETURN_IF_FAILED(mResidencyFence->WaitFor(lastUsedFenceValue));

            heap->RemoveFromList();
            heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_EVICTED);

            bytesEvicted += heap->GetSize();

            ComPtr<ID3D12Pageable> pageable;
            GPGMM_RETURN_IF_FAILED(heap->QueryInterface(IID_PPV_ARGS(&pageable)));

            objectsToEvict.push_back(pageable.Get());
        }

        if (objectsToEvict.size() > 0) {
            GPGMM_TRACE_EVENT_METRIC("GPU memory page-out (MB)", GPGMM_BYTES_TO_MB(bytesEvicted));

            const uint32_t objectEvictCount = static_cast<uint32_t>(objectsToEvict.size());
            GPGMM_RETURN_IF_FAILED(mDevice->Evict(objectEvictCount, objectsToEvict.data()),
                                   mDevice);

            DebugEvent(MessageId::kBudgetExceeded, this)
                << "GPU page-out. Number of allocations: " << objectsToEvict.size() << " ("
                << GetBytesToSizeInUnits(bytesEvicted) << ").";
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
            ErrorLog(ErrorCode::kInvalidArgument, this)
                << "ExecuteCommandLists is required to have at-least one residency "
                   "list to be called.";
            return GetErrorResult(ErrorCode::kInvalidArgument);
        }

        // TODO: support multiple command lists.
        if (count > 1) {
            ErrorLog(ErrorCode::kUnsupported, this)
                << "ExecuteCommandLists does not support multiple residency lists at this time. "
                   "Please call ExecuteCommandLists per residency list as a workaround, if needed.";
            return GetErrorResult(ErrorCode::kUnsupported);
        }

        GPGMM_RETURN_IF_FAILED(EnsureResidencyFenceExists());

        ResidencyList* residencyList = static_cast<ResidencyList*>(ppResidencyLists[0]);

        std::vector<ID3D12Pageable*> localHeapsToMakeResident;
        std::vector<ID3D12Pageable*> nonLocalHeapsToMakeResident;
        uint64_t localSizeToMakeResident = 0;
        uint64_t nonLocalSizeToMakeResident = 0;

        std::vector<ResidencyHeap*> heapsToMakeResident;
        for (IResidencyHeap* heap : *residencyList) {
            ResidencyHeap* backendHeap = FromAPI(heap);

            // Heaps that are locked resident are not tracked in the LRU cache.
            if (backendHeap->IsResidencyLocked()) {
                continue;
            }

            // ResidencyList can contain duplicates. We can skip them by checking if the heap's last
            // used fence is the same as the current one.
            if (backendHeap->GetLastUsedFenceValue() == mResidencyFence->GetCurrentFence()) {
                continue;
            }

            if (backendHeap->IsInList()) {
                // If the heap is already in the LRU, we must remove it and append again below to
                // update its position in the LRU.
                backendHeap->RemoveFromList();
            } else {
                ComPtr<ID3D12Pageable> pageable;
                GPGMM_RETURN_IF_FAILED(backendHeap->QueryInterface(IID_PPV_ARGS(&pageable)));

                if (backendHeap->GetMemorySegment() == RESIDENCY_HEAP_SEGMENT_LOCAL) {
                    localSizeToMakeResident += backendHeap->GetSize();
                    localHeapsToMakeResident.push_back(pageable.Get());
                } else {
                    nonLocalSizeToMakeResident += backendHeap->GetSize();
                    nonLocalHeapsToMakeResident.push_back(pageable.Get());
                }
            }

            // If we submit a command list to the GPU, we must ensure that heaps referenced by that
            // command list stay resident at least until that command list has finished execution.
            // Setting this serial unnecessarily can leave the LRU in a state where nothing is
            // eligible for eviction, even though some evictions may be possible.
            backendHeap->SetLastUsedFenceValue(mResidencyFence->GetCurrentFence());

            // Insert the heap into the appropriate LRU.
            InsertHeapInternal(backendHeap);

            // Temporarily track which heaps will be made resident. Once MakeResident() is called
            // on them will we transition them all together.
            heapsToMakeResident.push_back(backendHeap);

            // If the heap should be already resident, calling MakeResident again will be redundant.
            // Tell the developer the heap wasn't properly tracked by the residency manager.
            if (backendHeap->GetInfo().Status == RESIDENCY_HEAP_STATUS_UNKNOWN) {
                WarnLog(MessageId::kPerformanceWarning, this)
                    << "Residency state could not be determined for the heap (Heap="
                    << ToHexStr(backendHeap)
                    << "). This likely means the developer was attempting to make a "
                       "non-resource heap resident without calling lock/unlock first.";
            }
        }

        if (localSizeToMakeResident > 0) {
            const uint32_t numberOfObjectsToMakeResident =
                static_cast<uint32_t>(localHeapsToMakeResident.size());
            GPGMM_RETURN_IF_FAILED(
                MakeResident(RESIDENCY_HEAP_SEGMENT_LOCAL, localSizeToMakeResident,
                             numberOfObjectsToMakeResident, localHeapsToMakeResident.data()));
        } else if (nonLocalSizeToMakeResident > 0) {
            const uint32_t numberOfObjectsToMakeResident =
                static_cast<uint32_t>(nonLocalHeapsToMakeResident.size());
            GPGMM_RETURN_IF_FAILED(
                MakeResident(RESIDENCY_HEAP_SEGMENT_NON_LOCAL, nonLocalSizeToMakeResident,
                             numberOfObjectsToMakeResident, nonLocalHeapsToMakeResident.data()));
        }

        // Once MakeResident succeeds, we must assume the heaps are resident since D3D12 provides
        // no way of knowing for certain.
        for (ResidencyHeap* heap : heapsToMakeResident) {
            heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_RESIDENT);
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
            GPGMM_RETURN_IF_FAILED(mResidencyFence->Signal(pQueue));
        }

        // Keep memory segments up-to-date. This must always happen because if the budget
        // never changes (ie. not manually updated or through budget change events), the
        // residency manager wouldn't know what to page in or out.
        if (IsBudgetNotificationUpdatesDisabled()) {
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(RESIDENCY_HEAP_SEGMENT_LOCAL));
            GPGMM_RETURN_IF_FAILED(UpdateMemorySegmentInternal(RESIDENCY_HEAP_SEGMENT_NON_LOCAL));
        }

        GPGMM_TRACE_EVENT_OBJECT_CALL(
            "ResidencyManager.ExecuteCommandLists",
            (RESIDENCY_MANAGER_EXECUTE_COMMAND_LISTS_PARAMS{ppResidencyLists, count}));

        return S_OK;
    }

    HRESULT ResidencyManager::MakeResident(const RESIDENCY_HEAP_SEGMENT heapSegment,
                                           uint64_t sizeToMakeResident,
                                           uint32_t numberOfObjectsToMakeResident,
                                           ID3D12Pageable** allocations) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault, "ResidencyManager.MakeResident");

        GPGMM_RETURN_IF_FAILED(EvictInternal(sizeToMakeResident, heapSegment, nullptr));

        DebugEvent(MessageId::kBudgetExceeded, this)
            << "GPU page-in. Number of allocations: " << numberOfObjectsToMakeResident << " ("
            << GetBytesToSizeInUnits(sizeToMakeResident) << ").";

        // Decrease the overhead from using MakeResident, a synchronous call, by calling the
        // asynchronous MakeResident, called EnqueueMakeResident, instead first. Should
        // EnqueueMakeResident fail, fall-back to using synchronous MakeResident since we may be
        // able to continue after calling Evict again.
        ComPtr<ID3D12Device3> device3;
        if (SUCCEEDED(mDevice->QueryInterface(IID_PPV_ARGS(&device3)))) {
            GPGMM_RETURN_IF_FAILED(EnsureResidencyFenceExists());
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
                EvictInternal(mEvictSizeInBytes, heapSegment, &evictedSizeInBytes));
            if (evictedSizeInBytes == 0) {
                ErrorLog(ErrorCode::kBudgetInvalid, this)
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

        for (const auto& entry : mLocalMemorySegment.cache) {
            if (entry.value()->GetInfo().Status == RESIDENCY_HEAP_STATUS_RESIDENT) {
                result.CurrentHeapUsage += entry.value()->GetSize();
                result.CurrentHeapCount++;
            }
        }

        for (const auto& entry : mNonLocalMemorySegment.cache) {
            if (entry.value()->GetInfo().Status == RESIDENCY_HEAP_STATUS_RESIDENT) {
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

    // Starts updating memory budget from OS notifications.
    // Return True if successfully registered or False if error.
    HRESULT ResidencyManager::StartBudgetNotificationUpdates() {
        if (mBudgetNotificationUpdateEvent == nullptr) {
            std::shared_ptr<BudgetUpdateTask> task = CreateBudgetUpdateTask();
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

    void ResidencyManager::ReportSegmentInfoForTesting(RESIDENCY_HEAP_SEGMENT segmentGroup) {
        RESIDENCY_MEMORY_INFO* memorySegmentInfo = GetMemoryInfo(segmentGroup);
        ASSERT(memorySegmentInfo != nullptr);

        DebugLog(MessageId::kBudgetUpdated, this)
            << GetMemorySegmentName(segmentGroup, IsUMA()) << " GPU memory segment:";
        DebugLog(MessageId::kBudgetUpdated, this)
            << "\tBudget: " << GetBytesToSizeInUnits(memorySegmentInfo->Budget) << " ("
            << GetBytesToSizeInUnits(memorySegmentInfo->CurrentUsage) << " used).";

        if (memorySegmentInfo->CurrentReservation == 0) {
            DebugLog(MessageId::kBudgetUpdated, this)
                << "\tReserved: " << GetBytesToSizeInUnits(memorySegmentInfo->CurrentReservation)
                << " (" << GetBytesToSizeInUnits(memorySegmentInfo->AvailableForReservation)
                << " available).";
        }
    }

    HRESULT ResidencyManager::SetResidencyStatus(IResidencyHeap* pHeap,
                                                 const RESIDENCY_HEAP_STATUS& newStatus) {
        GPGMM_RETURN_IF_NULL(pHeap);

        ResidencyHeap* heap = FromAPI(pHeap);
        if (heap->GetInfo().IsLocked) {
            ErrorLog(ErrorCode::kBadOperation, this)
                << "Heap residency cannot be updated because it was locked. "
                   "Please unlock the heap before updating.";
            return GetErrorResult(ErrorCode::kBadOperation);
        }

        if (newStatus == RESIDENCY_HEAP_STATUS_UNKNOWN &&
            heap->GetInfo().Status != RESIDENCY_HEAP_STATUS_UNKNOWN) {
            ErrorLog(ErrorCode::kBadOperation, this)
                << "Heap residency cannot be unknown when previously known by the "
                   "residency manager. Check the status before updating the state.";
            return GetErrorResult(ErrorCode::kBadOperation);
        }

        heap->SetResidencyStatus(newStatus);
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
        GPGMM_RETURN_IF_FAILED(Fence::CreateFence(mDevice, mInitialFenceValue, &fencePtr));
        mResidencyFence.reset(fencePtr);
        return S_OK;
    }

    LPCWSTR ResidencyManager::GetDebugName() const {
        return DebugObject::GetDebugName();
    }

    HRESULT ResidencyManager::SetDebugName(LPCWSTR Name) {
        return DebugObject::SetDebugNameImpl(Name);
    }

    ID3D12Device* ResidencyManager::GetDevice() const {
        return mDevice;
    }

}  // namespace gpgmm::d3d12
