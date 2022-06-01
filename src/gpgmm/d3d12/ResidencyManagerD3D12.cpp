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

#include "gpgmm/d3d12/ResidencyManagerD3D12.h"

#include "gpgmm/common/Debug.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/FenceD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencySetD3D12.h"
#include "gpgmm/utils/Math.h"

#include <algorithm>
#include <vector>

namespace gpgmm { namespace d3d12 {

    static constexpr uint32_t kDefaultEvictBatchSize = 50ll * 1024ll * 1024ll;  // 50MB
    static constexpr float kDefaultVideoMemoryBudget = 0.95f;               // 95%

    // static
    HRESULT ResidencyManager::CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                                     ResidencyManager** residencyManagerOut) {
        // Residency manager needs it's own fence to know when heaps are no longer being used by the
        // GPU.
        std::unique_ptr<Fence> residencyFence;
        {
            Fence* ptr = nullptr;
            ReturnIfFailed(
                Fence::CreateFence(descriptor.Device, descriptor.InitialFenceValue, &ptr));
            residencyFence.reset(ptr);
        }

        if (descriptor.VideoMemoryBudget != 0 && descriptor.Budget != 0) {
            gpgmm::WarningLog()
                << "Video memory budget was ignored since a budget was already specified.";
        }

        std::unique_ptr<ResidencyManager> residencyManager = std::unique_ptr<ResidencyManager>(
            new ResidencyManager(descriptor, std::move(residencyFence)));

        // Set the initial video memory limits per segment.
        ReturnIfFailed(residencyManager->UpdateVideoMemorySegments());

        // D3D12 has non-zero memory usage even before any resources have been created, and this
        // value can vary by OS enviroment. By adding this in addition to the artificial budget
        // limit, we can create a predictable and reproducible budget.
        if (descriptor.Budget > 0) {
            DXGI_QUERY_VIDEO_MEMORY_INFO* localVideoMemorySegmentInfo =
                residencyManager->GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_LOCAL);

            localVideoMemorySegmentInfo->Budget =
                localVideoMemorySegmentInfo->CurrentUsage + descriptor.Budget;
            if (!descriptor.IsUMA) {
                DXGI_QUERY_VIDEO_MEMORY_INFO* nonLocalVideoMemorySegmentInfo =
                    residencyManager->GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL);

                nonLocalVideoMemorySegmentInfo->Budget =
                    nonLocalVideoMemorySegmentInfo->CurrentUsage + descriptor.Budget;
            }
        }

        *residencyManagerOut = residencyManager.release();

        return S_OK;
    }

    ResidencyManager::ResidencyManager(const RESIDENCY_DESC& descriptor,
                                       std::unique_ptr<Fence> fence)
        : mDevice(descriptor.Device),
          mAdapter(descriptor.Adapter),
          mFence(std::move(fence)),
          mVideoMemoryBudget(descriptor.VideoMemoryBudget == 0 ? kDefaultVideoMemoryBudget
                                                               : descriptor.VideoMemoryBudget),
          mIsBudgetRestricted(descriptor.Budget > 0),
          mEvictBatchSize(descriptor.EvictBatchSize == 0 ? kDefaultEvictBatchSize
                                                         : descriptor.EvictBatchSize),
          mIsUMA(descriptor.IsUMA) {
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);

        ASSERT(mDevice != nullptr);
        ASSERT(mAdapter != nullptr);
        ASSERT(mFence != nullptr);
    }

    ResidencyManager::~ResidencyManager() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
    }

    const char* ResidencyManager::GetTypename() const {
        return "ResidencyManager";
    }

    // Increments number of locks on a heap to ensure the heap remains resident.
    HRESULT ResidencyManager::LockHeap(Heap* heap) {
        std::lock_guard<std::mutex> lock(mMutex);

        if (heap == nullptr) {
            return E_INVALIDARG;
        }

        if (!heap->IsResident()) {
            ComPtr<ID3D12Pageable> pageable;
            ReturnIfFailed(heap->As(&pageable));
            ReturnIfFailed(MakeResident(heap->GetMemorySegmentGroup(), heap->GetSize(), 1,
                                        pageable.GetAddressOf()));
        }

        // Since we can't evict the heap, it's unnecessary to track the heap in the LRU Cache.
        if (heap->IsInResidencyLRUCache()) {
            heap->RemoveFromList();
        }

        heap->AddResidencyLockRef();

        return S_OK;
    }

    // Decrements number of locks on a heap. When the number of locks becomes zero, the heap is
    // inserted into the LRU cache and becomes eligible for eviction.
    HRESULT ResidencyManager::UnlockHeap(Heap* heap) {
        std::lock_guard<std::mutex> lock(mMutex);

        if (heap == nullptr) {
            return E_INVALIDARG;
        }

        if (!heap->IsResidencyLocked()) {
            return E_FAIL;
        }

        if (heap->IsInResidencyLRUCache()) {
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

        return S_OK;
    }

    HRESULT ResidencyManager::InsertHeap(Heap* heap) {
        std::lock_guard<std::mutex> lock(mMutex);
        return InsertHeapInternal(heap);
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

        cache->push_back(heap);

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
        uint64_t reservation,
        uint64_t* reservationOut) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResidencyManager.SetVideoMemoryReservation");

        std::lock_guard<std::mutex> lock(mMutex);

        DXGI_QUERY_VIDEO_MEMORY_INFO* videoMemorySegmentInfo =
            GetVideoMemoryInfo(memorySegmentGroup);

        videoMemorySegmentInfo->AvailableForReservation = reservation;

        ReturnIfFailed(QueryVideoMemoryInfo(memorySegmentGroup, videoMemorySegmentInfo));

        *reservationOut = videoMemorySegmentInfo->CurrentReservation;

        return S_OK;
    }

    HRESULT ResidencyManager::QueryVideoMemoryInfo(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
        DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfo) const {
        DXGI_QUERY_VIDEO_MEMORY_INFO queryVideoMemoryInfoOut;
        ReturnIfFailed(
            mAdapter->QueryVideoMemoryInfo(0, memorySegmentGroup, &queryVideoMemoryInfoOut));

        // The video memory budget provided by QueryVideoMemoryInfo is defined by the operating
        // system, and may be lower than expected in certain scenarios. Under memory pressure, we
        // cap the external reservation to half the available budget, which prevents the external
        // component from consuming a disproportionate share of memory and ensures that Dawn can
        // continue to make forward progress. Note the choice to halve memory is arbitrarily chosen
        // and subject to future experimentation.
        pVideoMemoryInfo->CurrentReservation =
            std::min(queryVideoMemoryInfoOut.Budget / 2, pVideoMemoryInfo->AvailableForReservation);

        pVideoMemoryInfo->CurrentUsage =
            queryVideoMemoryInfoOut.CurrentUsage - pVideoMemoryInfo->CurrentReservation;

        // If we're restricting the budget, leave the budget as is.
        if (!mIsBudgetRestricted) {
            pVideoMemoryInfo->Budget = static_cast<uint64_t>(
                (queryVideoMemoryInfoOut.Budget - pVideoMemoryInfo->CurrentReservation) *
                mVideoMemoryBudget);
        }

        TRACE_COUNTER1(
            TraceEventCategory::Default,
            ToString((memorySegmentGroup == DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL) ? "Dedicated"
                                                                                 : "Shared",
                     " GPU memory utilization (%)")
                .c_str(),
            (pVideoMemoryInfo->CurrentUsage > pVideoMemoryInfo->Budget)
                ? 100
                : SafeDivison(pVideoMemoryInfo->CurrentUsage, pVideoMemoryInfo->Budget) * 100);

        // Reservations are optional.
        if (pVideoMemoryInfo->CurrentReservation > 0) {
            TRACE_COUNTER1(
                TraceEventCategory::Default,
                ToString((memorySegmentGroup == DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL) ? "Dedicated"
                                                                                     : "Shared",
                         " GPU memory reserved (MB)")
                    .c_str(),
                pVideoMemoryInfo->CurrentReservation / 1e6);
        }

        return S_OK;
    }

    HRESULT ResidencyManager::UpdateVideoMemorySegments() {
        DXGI_QUERY_VIDEO_MEMORY_INFO* queryVideoMemoryInfo =
            GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_LOCAL);

        ReturnIfFailed(QueryVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_LOCAL, queryVideoMemoryInfo));
        if (!mIsUMA) {
            queryVideoMemoryInfo = GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL);
            ReturnIfFailed(
                QueryVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL, queryVideoMemoryInfo));
        }
        return S_OK;
    }

    HRESULT ResidencyManager::Evict(uint64_t evictSizeInBytes,
                                    const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        std::lock_guard<std::mutex> lock(mMutex);
        return EvictInternal(evictSizeInBytes, memorySegmentGroup);
    }

    // Evicts |evictSizeInBytes| bytes of memory in |memorySegmentGroup| and returns the number of
    // bytes evicted.
    HRESULT ResidencyManager::EvictInternal(uint64_t evictSizeInBytes,
                                            const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                            uint64_t* evictedSizeInBytesOut) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResidencyManager.Evict");

        DXGI_QUERY_VIDEO_MEMORY_INFO* videoMemorySegmentInfo =
            GetVideoMemoryInfo(memorySegmentGroup);
        ReturnIfFailed(QueryVideoMemoryInfo(memorySegmentGroup, videoMemorySegmentInfo));

        const uint64_t currentUsageAfterEvict =
            evictSizeInBytes + videoMemorySegmentInfo->CurrentUsage;

        // Return if we will remain under budget after evict.
        if (currentUsageAfterEvict < videoMemorySegmentInfo->Budget) {
            return S_OK;
        }

        // Any time we need to make something resident, we must check that we have enough free
        // memory to make the new object resident while also staying within budget. If there isn't
        // enough memory, we should evict until there is.
        std::vector<ID3D12Pageable*> objectsToEvict;
        const uint64_t sizeNeededToBeUnderBudget =
            currentUsageAfterEvict - videoMemorySegmentInfo->Budget;
        uint64_t evictedSizeInBytes = 0;
        while (evictedSizeInBytes < sizeNeededToBeUnderBudget) {
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
            if (lastUsedFenceValue == mFence->GetCurrentFence()) {
                break;
            }

            // We must ensure that any previous use of a resource has completed before the resource
            // can be evicted.
            ReturnIfFailed(mFence->WaitFor(lastUsedFenceValue));

            heap->RemoveFromList();

            evictedSizeInBytes += heap->GetSize();

            ComPtr<ID3D12Pageable> pageable;
            ReturnIfFailed(heap->As(&pageable));

            objectsToEvict.push_back(pageable.Get());
        }

        if (objectsToEvict.size() > 0) {
            TRACE_COUNTER1(TraceEventCategory::Default, "GPU memory page-out (MB)",
                           evictedSizeInBytes / 1e6);

            const uint32_t objectEvictCount = static_cast<uint32_t>(objectsToEvict.size());
            ReturnIfFailed(mDevice->Evict(objectEvictCount, objectsToEvict.data()));

            InfoEvent("GPU page-out") << "Number of allocations: " << objectsToEvict.size() << " ("
                                      << evictedSizeInBytes << " bytes).";
        }

        if (evictedSizeInBytesOut != nullptr) {
            *evictedSizeInBytesOut = evictedSizeInBytes;
        }
        return S_OK;
    }

    // Given a list of heaps that are pending usage, this function will estimate memory needed,
    // evict resources until enough space is available, then make resident any heaps scheduled for
    // usage.
    HRESULT ResidencyManager::ExecuteCommandLists(ID3D12CommandQueue* queue,
                                                  ID3D12CommandList* const* commandLists,
                                                  ResidencySet* const* residencySets,
                                                  uint32_t count) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResidencyManager.ExecuteCommandLists");

        std::lock_guard<std::mutex> lock(mMutex);

        // TODO: support multiple command lists.
        if (count > 1) {
            return E_NOTIMPL;
        }

        // Keep video memory segments up-to-date. This must always happen because tests may
        // want to execute a no-op to get the current budget and usage.
        ReturnIfFailed(UpdateVideoMemorySegments());

        if (count == 0) {
            return S_OK;
        }

        ID3D12CommandList* commandList = commandLists[0];
        ResidencySet* residencySet = residencySets[0];

        std::vector<ID3D12Pageable*> localHeapsToMakeResident;
        std::vector<ID3D12Pageable*> nonLocalHeapsToMakeResident;
        uint64_t localSizeToMakeResident = 0;
        uint64_t nonLocalSizeToMakeResident = 0;

        for (Heap* heap : *residencySet) {
            // Heaps that are locked resident are not tracked in the LRU cache.
            if (heap->IsResidencyLocked()) {
                continue;
            }

            if (heap->IsInResidencyLRUCache()) {
                // If the heap is already in the LRU, we must remove it and append again below to
                // update its position in the LRU.
                heap->RemoveFromList();
            } else {
                ComPtr<ID3D12Pageable> pageable;
                ReturnIfFailed(heap->As(&pageable));

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
            heap->SetLastUsedFenceValue(mFence->GetCurrentFence());

            // Insert the heap into the appropriate LRU.
            InsertHeapInternal(heap);
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

        if (localSizeToMakeResident > 0 || nonLocalSizeToMakeResident > 0) {
            TRACE_COUNTER1(TraceEventCategory::Default, "GPU memory page-in (MB)",
                           (localSizeToMakeResident + nonLocalSizeToMakeResident) / 1e6);
        }

        queue->ExecuteCommandLists(count, &commandList);
        ReturnIfFailed(mFence->Signal(queue));

        GPGMM_TRACE_EVENT_OBJECT_CALL("ResidencyManager.ExecuteCommandLists",
                                      (EXECUTE_COMMAND_LISTS_DESC{residencySets, count}));

        return S_OK;
    }

    HRESULT ResidencyManager::MakeResident(const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup,
                                           uint64_t sizeToMakeResident,
                                           uint32_t numberOfObjectsToMakeResident,
                                           ID3D12Pageable** allocations) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResidencyManager.MakeResident");

        ReturnIfFailed(EvictInternal(sizeToMakeResident, memorySegmentGroup, nullptr));

        InfoEvent("GPU page-in") << "Number of allocations: " << numberOfObjectsToMakeResident
                                 << " (" << sizeToMakeResident << " bytes).";

        // Decrease the overhead from using MakeResident, a synchronous call, by calling the
        // asynchronous MakeResident, called EnqueueMakeResident, instead first. Should
        // EnqueueMakeResident fail, fall-back to using synchronous MakeResident since we may be
        // able to continue after calling Evict again.
        if (mDevice3 != nullptr) {
            ReturnIfSucceeded(mDevice3->EnqueueMakeResident(
                D3D12_RESIDENCY_FLAG_NONE, numberOfObjectsToMakeResident, allocations,
                mFence->GetFence(), mFence->GetLastSignaledFence() + 1));
        }

        // A MakeResident call can fail if there's not enough available memory. This
        // could occur when there's significant fragmentation or if the allocation size
        // estimates are incorrect. We may be able to continue execution by evicting some
        // more memory and calling MakeResident again.
        while (FAILED(mDevice->MakeResident(numberOfObjectsToMakeResident, allocations))) {
            // If nothing can be evicted after MakeResident has failed, we cannot continue
            // execution and must throw a fatal error.
            uint64_t evictedSizeInBytes = 0;
            ReturnIfFailed(EvictInternal(mEvictBatchSize, memorySegmentGroup, &evictedSizeInBytes));
            if (evictedSizeInBytes == 0) {
                return E_OUTOFMEMORY;
            }
        }

        return S_OK;
    }
}}  // namespace gpgmm::d3d12
