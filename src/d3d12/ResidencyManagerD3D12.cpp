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

#include "src/d3d12/ResidencyManagerD3D12.h"

#include "src/d3d12/DefaultsD3D12.h"
#include "src/d3d12/FenceD3D12.h"
#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResidencySetD3D12.h"
#include "src/d3d12/UtilsD3D12.h"

#include <algorithm>
#include <vector>

namespace gpgmm { namespace d3d12 {

    // static
    HRESULT ResidencyManager::CreateResidencyManager(ComPtr<ID3D12Device> device,
                                                     ComPtr<IDXGIAdapter> adapter,
                                                     bool isUMA,
                                                     float videoMemoryBudget,
                                                     uint64_t availableForResourcesBudget,
                                                     ResidencyManager** residencyManagerOut) {
        // Requires DXGI 1.4 due to IDXGIAdapter3::QueryVideoMemoryInfo.
        Microsoft::WRL::ComPtr<IDXGIAdapter3> adapter3;
        ReturnIfFailed(adapter.As(&adapter3));

        std::unique_ptr<ResidencyManager> residencyManager = std::unique_ptr<ResidencyManager>(
            new ResidencyManager(std::move(device), std::move(adapter3), isUMA, videoMemoryBudget,
                                 availableForResourcesBudget));

        // Query and set the video memory limits per segment.
        ReturnIfFailed(residencyManager->UpdateMemorySegmentInfo(
            &residencyManager->mLocalMemorySegment, DXGI_MEMORY_SEGMENT_GROUP_LOCAL));
        if (!isUMA) {
            ReturnIfFailed(residencyManager->UpdateMemorySegmentInfo(
                &residencyManager->mNonLocalMemorySegment, DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL));
        }

        *residencyManagerOut = residencyManager.release();

        return S_OK;
    }

    ResidencyManager::ResidencyManager(ComPtr<ID3D12Device> device,
                                       ComPtr<IDXGIAdapter3> adapter3,
                                       bool isUMA,
                                       float videoMemoryBudgetLimit,
                                       uint64_t availableForResourcesBudget)
        : mDevice(device),
          mAdapter(adapter3),
          mIsUMA(isUMA),
          mMemoryBudgetLimit(videoMemoryBudgetLimit == 0 ? kDefaultMaxVideoMemoryBudget
                                                         : videoMemoryBudgetLimit),
          mAvailableForResourcesBudget(availableForResourcesBudget),
          mFence(new Fence(device, 0)) {
        // There is a non-zero memory usage even before any resources have been created, and this
        // value can vary by enviroment. By adding this in addition to the artificial budget limit,
        // we can create a predictable and reproducible budget.
        if (mAvailableForResourcesBudget > 0) {
            mLocalMemorySegment.budget =
                mLocalMemorySegment.currentUsage + mAvailableForResourcesBudget;
            if (!mIsUMA) {
                mNonLocalMemorySegment.budget =
                    mNonLocalMemorySegment.currentUsage + mAvailableForResourcesBudget;
            }
        }
    }

    ResidencyManager::~ResidencyManager() {
    }

    // Increments number of locks on a heap to ensure the heap remains resident.
    HRESULT ResidencyManager::LockHeap(Heap* heap) {
        if (heap == nullptr) {
            return E_INVALIDARG;
        }

        if (!heap->IsResident()) {
            ID3D12Pageable* pageable = heap->GetPageable();
            ReturnIfFailed(
                MakeResident(heap->GetMemorySegmentGroup(), heap->GetSize(), 1, &pageable));
        }

        // Since we can't evict the heap, it's unnecessary to track the heap in the LRU Cache.
        if (heap->IsInResidencyLRUCache()) {
            heap->RemoveFromList();
        }

        heap->IncrementResidencyLock();

        return S_OK;
    }

    // Decrements number of locks on a heap. When the number of locks becomes zero, the heap is
    // inserted into the LRU cache and becomes eligible for eviction.
    HRESULT ResidencyManager::UnlockHeap(Heap* heap) {
        if (heap == nullptr) {
            return E_INVALIDARG;
        }

        if (!heap->IsResidencyLocked()) {
            return E_FAIL;
        }

        if (heap->IsInResidencyLRUCache()) {
            return E_FAIL;
        }

        heap->DecrementResidencyLock();

        // If another lock still exists on the heap, nothing further should be done.
        if (heap->IsResidencyLocked()) {
            return S_OK;
        }

        // When all locks have been removed, the resource remains resident and becomes tracked in
        // the corresponding LRU.
        return InsertHeap(heap);
    }

    // Returns the appropriate MemorySegmentInfo for a given DXGI_MEMORY_SEGMENT_GROUP.
    ResidencyManager::MemorySegmentInfo* ResidencyManager::GetMemorySegmentInfo(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        switch (memorySegmentGroup) {
            case DXGI_MEMORY_SEGMENT_GROUP_LOCAL:
                return &mLocalMemorySegment;
            case DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL:
                ASSERT(!mIsUMA);
                return &mNonLocalMemorySegment;
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
        MemorySegmentInfo* memorySegmentInfo = GetMemorySegmentInfo(memorySegmentGroup);

        memorySegmentInfo->reservation = reservation;

        ReturnIfFailed(UpdateMemorySegmentInfo(memorySegmentInfo, memorySegmentGroup));

        *reservationOut = memorySegmentInfo->currentReservation;

        return S_OK;
    }

    HRESULT ResidencyManager::UpdateMemorySegmentInfo(
        MemorySegmentInfo* memorySegmentInfo,
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        DXGI_QUERY_VIDEO_MEMORY_INFO queryVideoMemoryInfo;

        ReturnIfFailed(
            mAdapter->QueryVideoMemoryInfo(0, memorySegmentGroup, &queryVideoMemoryInfo));

        // The video memory budget provided by QueryVideoMemoryInfo is defined by the operating
        // system, and may be lower than expected in certain scenarios. Under memory pressure, we
        // cap the external reservation to half the available budget, which prevents the external
        // component from consuming a disproportionate share of memory and ensures that Dawn can
        // continue to make forward progress. Note the choice to halve memory is arbitrarily chosen
        // and subject to future experimentation.
        memorySegmentInfo->currentReservation =
            std::min(queryVideoMemoryInfo.Budget / 2, memorySegmentInfo->reservation);

        memorySegmentInfo->currentUsage =
            queryVideoMemoryInfo.CurrentUsage - memorySegmentInfo->currentReservation;

        // If we're restricting the budget, leave the budget as is.
        if (mAvailableForResourcesBudget > 0) {
            return S_OK;
        }

        memorySegmentInfo->budget = static_cast<uint64_t>(
            (queryVideoMemoryInfo.Budget - memorySegmentInfo->currentReservation) *
            mMemoryBudgetLimit);

        return S_OK;
    }

    // Any time we need to make something resident, we must check that we have enough free memory to
    // make the new object resident while also staying within budget. If there isn't enough
    // memory, we should evict until there is. Returns the number of bytes evicted.
    HRESULT ResidencyManager::Evict(uint64_t sizeToMakeResident,
                                    const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                    uint64_t* sizeEvictedOut) {
        MemorySegmentInfo* memorySegmentInfo = GetMemorySegmentInfo(memorySegmentGroup);

        ReturnIfFailed(UpdateMemorySegmentInfo(memorySegmentInfo, memorySegmentGroup));

        const uint64_t currentUsageAfterMakeResident =
            sizeToMakeResident + memorySegmentInfo->currentUsage;

        // Return when we can call MakeResident and remain under budget.
        if (currentUsageAfterMakeResident < memorySegmentInfo->budget) {
            return 0;
        }

        std::vector<ID3D12Pageable*> resourcesToEvict;
        uint64_t sizeNeededToBeUnderBudget =
            currentUsageAfterMakeResident - memorySegmentInfo->budget;
        uint64_t sizeEvicted = 0;
        while (sizeEvicted < sizeNeededToBeUnderBudget) {
            // If the cache is empty, allow execution to continue. Note that fully
            // emptying the cache is undesirable, because it can mean either 1) the cache is not
            // accurately accounting for GPU allocations, or 2) an external component is
            // using all of the budget and is starving us, which will cause thrash.
            Cache* cache = &memorySegmentInfo->lruCache;
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

            sizeEvicted += heap->GetSize();
            resourcesToEvict.push_back(heap->GetPageable());
        }

        if (resourcesToEvict.size() > 0) {
            const uint32_t numOfResources = static_cast<uint32_t>(resourcesToEvict.size());
            ReturnIfFailed(mDevice->Evict(numOfResources, resourcesToEvict.data()));
        }

        if (sizeEvictedOut != nullptr) {
            *sizeEvictedOut = sizeEvicted;
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
        // TODO: support multiple command lists.
        ASSERT(count == 1);
        ID3D12CommandList* commandList = commandLists[0];
        ResidencySet* residencySet = residencySets[0];

        std::vector<ID3D12Pageable*> localHeapsToMakeResident;
        std::vector<ID3D12Pageable*> nonLocalHeapsToMakeResident;
        uint64_t localSizeToMakeResident = 0;
        uint64_t nonLocalSizeToMakeResident = 0;

        for (size_t i = 0; i < residencySet->mToMakeResident.size(); i++) {
            Heap* heap = residencySet->mToMakeResident[i];

            // Heaps that are locked resident are not tracked in the LRU cache.
            if (heap->IsResidencyLocked()) {
                continue;
            }

            if (heap->IsInResidencyLRUCache()) {
                // If the heap is already in the LRU, we must remove it and append again below to
                // update its position in the LRU.
                heap->RemoveFromList();
            } else {
                if (heap->GetMemorySegmentGroup() == DXGI_MEMORY_SEGMENT_GROUP_LOCAL) {
                    localSizeToMakeResident += heap->GetSize();
                    localHeapsToMakeResident.push_back(heap->GetPageable());
                } else {
                    nonLocalSizeToMakeResident += heap->GetSize();
                    nonLocalHeapsToMakeResident.push_back(heap->GetPageable());
                }
            }

            // If we submit a command list to the GPU, we must ensure that heaps referenced by that
            // command list stay resident at least until that command list has finished execution.
            // Setting this serial unnecessarily can leave the LRU in a state where nothing is
            // eligible for eviction, even though some evictions may be possible.
            heap->SetLastUsedFenceValue(mFence->GetCurrentFence());

            // Insert the heap into the appropriate LRU.
            InsertHeap(heap);
        }

        HRESULT hr = S_OK;
        if (localSizeToMakeResident > 0) {
            const uint32_t numOfresources = static_cast<uint32_t>(localHeapsToMakeResident.size());
            hr = MakeResident(DXGI_MEMORY_SEGMENT_GROUP_LOCAL, localSizeToMakeResident,
                              numOfresources, localHeapsToMakeResident.data());
        } else if (nonLocalSizeToMakeResident > 0) {
            ASSERT(!mIsUMA);
            const uint32_t numOfResources =
                static_cast<uint32_t>(nonLocalHeapsToMakeResident.size());
            hr = MakeResident(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL, nonLocalSizeToMakeResident,
                              numOfResources, nonLocalHeapsToMakeResident.data());
        }

        queue->ExecuteCommandLists(count, &commandList);

        if (SUCCEEDED(hr)) {
            ReturnIfFailed(mFence->Signal(queue));
        }

        return hr;
    }

    HRESULT ResidencyManager::MakeResident(const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup,
                                           uint64_t sizeToMakeResident,
                                           uint32_t numberOfObjectsToMakeResident,
                                           ID3D12Pageable** allocations) {
        ReturnIfFailed(Evict(sizeToMakeResident, memorySegmentGroup, nullptr));

        // Note that MakeResident is a synchronous function and can add a significant
        // overhead to command recording. In the future, it may be possible to decrease this
        // overhead by using MakeResident on a secondary thread, or by instead making use of
        // the EnqueueMakeResident function (which is not available on all Windows 10
        // platforms).
        HRESULT hr = mDevice->MakeResident(numberOfObjectsToMakeResident, allocations);

        // A MakeResident call can fail if there's not enough available memory. This
        // could occur when there's significant fragmentation or if the allocation size
        // estimates are incorrect. We may be able to continue execution by evicting some
        // more memory and calling MakeResident again.
        while (FAILED(hr)) {
            uint64_t sizeEvicted = 0;
            ReturnIfFailed(
                Evict(kDefaultResidentResourceEvictSize, memorySegmentGroup, &sizeEvicted));

            // If nothing can be evicted after MakeResident has failed, we cannot continue
            // execution and must throw a fatal error.
            if (sizeEvicted == 0) {
                return E_OUTOFMEMORY;
            }

            hr = mDevice->MakeResident(numberOfObjectsToMakeResident, allocations);
        }

        return S_OK;
    }

    // Inserts a heap at the bottom of the LRU. The passed heap must be resident or scheduled to
    // become resident within the current serial. Failing to call this function when an allocation
    // is implicitly made resident will cause the residency manager to view the allocation as
    // non-resident and call MakeResident - which will make D3D12's internal residency refcount on
    // the allocation out of sync with Dawn.
    HRESULT ResidencyManager::InsertHeap(Heap* heap) {
        if (heap == nullptr) {
            return E_INVALIDARG;
        }

        // Heap already exists in the cache.
        if (heap->IsInList()) {
            return E_INVALIDARG;
        }

        MemorySegmentInfo* memorySegment = GetMemorySegmentInfo(heap->GetMemorySegmentGroup());
        ASSERT(memorySegment != nullptr);

        memorySegment->lruCache.Append(heap);
        ASSERT(heap->IsInList());

        return S_OK;
    }
}}  // namespace gpgmm::d3d12
