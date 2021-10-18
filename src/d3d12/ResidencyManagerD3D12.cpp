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

    ResidencyManager::ResidencyManager(ComPtr<ID3D12Device> device,
                                       ComPtr<IDXGIAdapter3> adapter3,
                                       bool isUMA,
                                       float videoMemoryBudgetLimit,
                                       uint64_t mTotalResourceBudgetLimit)
        : mDevice(device),
          mAdapter(adapter3),
          mIsUMA(isUMA),
          mVideoMemoryBudgetLimit(videoMemoryBudgetLimit == 0 ? kDefaultMaxVideoMemoryBudget
                                                              : videoMemoryBudgetLimit),
          mTotalResourceBudgetLimit(mTotalResourceBudgetLimit),
          mFence(new Fence(device, 0)) {
        // Query and set the video memory limits for each segment.
        UpdateVideoMemorySegmentInfo(&mVideoMemoryInfo.localVideoMemorySegment);
        if (!mIsUMA) {
            UpdateVideoMemorySegmentInfo(&mVideoMemoryInfo.nonLocalVideoMemorySegment);
        }

        // There is a non-zero memory usage even before any resources have been created, and this
        // value can vary by enviroment. By adding this in addition to the artificial budget cap, we
        // can create a predictable and reproducible budget.
        if (mTotalResourceBudgetLimit > 0) {
            mVideoMemoryInfo.localVideoMemorySegment.budget =
                mVideoMemoryInfo.localVideoMemorySegment.usage + mTotalResourceBudgetLimit;
            if (!mIsUMA) {
                mVideoMemoryInfo.nonLocalVideoMemorySegment.budget =
                    mVideoMemoryInfo.nonLocalVideoMemorySegment.usage + mTotalResourceBudgetLimit;
            }
        }
    }

    ResidencyManager::~ResidencyManager() {
    }

    // Increments number of locks on a heap to ensure the heap remains resident.
    HRESULT ResidencyManager::LockHeap(Heap* heap) {
        // If the heap isn't already resident, make it resident.
        if (!heap->IsInResidencyLRUCache() && !heap->IsResidencyLocked()) {
            ID3D12Pageable* pageable = heap->GetPageable();
            uint64_t size = heap->GetSize();

            ReturnIfFailed(MakeResident(heap->GetMemorySegmentGroup(), size, 1, &pageable));
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
    void ResidencyManager::UnlockHeap(Heap* heap) {
        ASSERT(heap->IsResidencyLocked());
        ASSERT(!heap->IsInResidencyLRUCache());
        heap->DecrementResidencyLock();

        // If another lock still exists on the heap, nothing further should be done.
        if (heap->IsResidencyLocked()) {
            return;
        }

        // When all locks have been removed, the resource remains resident and becomes tracked in
        // the corresponding LRU.
        InsertHeap(heap);
    }

    // Returns the appropriate VideoMemorySegmentInfo for a given DXGI_MEMORY_SEGMENT_GROUP.
    ResidencyManager::VideoMemorySegmentInfo* ResidencyManager::GetVideoMemorySegmentInfo(
        const DXGI_MEMORY_SEGMENT_GROUP& dxgiMemorySegmentGroup) {
        switch (dxgiMemorySegmentGroup) {
            case DXGI_MEMORY_SEGMENT_GROUP_LOCAL:
                return &mVideoMemoryInfo.localVideoMemorySegment;
            case DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL:
                ASSERT(!mIsUMA);
                return &mVideoMemoryInfo.nonLocalVideoMemorySegment;
            default:
                UNREACHABLE();
                return nullptr;
        }
    }

    // Sends the minimum required physical video memory for an application, to this residency
    // manager. Returns the amount of memory reserved, which may be less then the |reservation| when
    // under video memory pressure.
    HRESULT ResidencyManager::SetVideoMemoryReservation(
        const DXGI_MEMORY_SEGMENT_GROUP& dxgiMemorySegmentGroup,
        uint64_t reservation,
        uint64_t* reservationOut) {
        VideoMemorySegmentInfo* videoMemorySegment =
            GetVideoMemorySegmentInfo(dxgiMemorySegmentGroup);

        videoMemorySegment->externalRequest = reservation;

        UpdateVideoMemorySegmentInfo(videoMemorySegment);

        *reservationOut = videoMemorySegment->externalReservation;

        return S_OK;
    }

    void ResidencyManager::UpdateVideoMemorySegmentInfo(
        VideoMemorySegmentInfo* videoMemorySegment) {
        DXGI_QUERY_VIDEO_MEMORY_INFO queryVideoMemoryInfo;

        mAdapter->QueryVideoMemoryInfo(0, videoMemorySegment->dxgiMemorySegmentGroup,
                                       &queryVideoMemoryInfo);

        // The video memory budget provided by QueryVideoMemoryInfo is defined by the operating
        // system, and may be lower than expected in certain scenarios. Under memory pressure, we
        // cap the external reservation to half the available budget, which prevents the external
        // component from consuming a disproportionate share of memory and ensures that Dawn can
        // continue to make forward progress. Note the choice to halve memory is arbitrarily chosen
        // and subject to future experimentation.
        videoMemorySegment->externalReservation =
            std::min(queryVideoMemoryInfo.Budget / 2, videoMemorySegment->externalRequest);

        videoMemorySegment->usage =
            queryVideoMemoryInfo.CurrentUsage - videoMemorySegment->externalReservation;

        // If we're restricting the budget, leave the budget as is.
        if (mTotalResourceBudgetLimit > 0) {
            return;
        }

        videoMemorySegment->budget =
            (queryVideoMemoryInfo.Budget - videoMemorySegment->externalReservation) *
            mVideoMemoryBudgetLimit;
    }

    // Removes a heap from the LRU and returns the least recently used heap when possible. Returns
    // nullptr when nothing further can be evicted.
    HRESULT ResidencyManager::EvictHeap(VideoMemorySegmentInfo* videoMemorySegment,
                                        Heap** ppEvictedHeapOut) {
        // If the LRU is empty, return nullptr to allow execution to continue. Note that fully
        // emptying the LRU is undesirable, because it can mean either 1) the LRU is not accurately
        // accounting for Dawn's GPU allocations, or 2) a component external to Dawn is using all of
        // the process budget and starving Dawn, which will cause thrash.
        if (videoMemorySegment->lruCache.empty()) {
            return S_OK;
        }

        Heap* heap = videoMemorySegment->lruCache.head()->value();

        const uint64_t lastUsedFenceValue = heap->GetLastUsedFenceValue();

        // If the next candidate for eviction was inserted into the LRU during the pending
        // submission, it is because more memory is being used in a single command list than is
        // available. In this scenario, we cannot make any more resources resident and thrashing
        // must occur.
        if (lastUsedFenceValue == mFence->GetCurrentFence()) {
            return S_OK;
        }

        // We must ensure that any previous use of a resource has completed before the resource can
        // be evicted.
        ReturnIfFailed(mFence->WaitFor(lastUsedFenceValue));

        heap->RemoveFromList();

        *ppEvictedHeapOut = heap;

        return S_OK;
    }

    // Any time we need to make something resident, we must check that we have enough free memory to
    // make the new object resident while also staying within budget. If there isn't enough
    // memory, we should evict until there is. Returns the number of bytes evicted.
    HRESULT ResidencyManager::Evict(uint64_t sizeToMakeResident,
                                    const DXGI_MEMORY_SEGMENT_GROUP& dxgiMemorySegmentGroup,
                                    uint64_t* sizeEvictedOut) {
        VideoMemorySegmentInfo* videoMemorySegmentInfo =
            GetVideoMemorySegmentInfo(dxgiMemorySegmentGroup);

        UpdateVideoMemorySegmentInfo(videoMemorySegmentInfo);

        const uint64_t memoryUsageAfterMakeResident =
            sizeToMakeResident + videoMemorySegmentInfo->usage;

        // Return when we can call MakeResident and remain under budget.
        if (memoryUsageAfterMakeResident < videoMemorySegmentInfo->budget) {
            return 0;
        }

        std::vector<ID3D12Pageable*> resourcesToEvict;
        uint64_t sizeNeededToBeUnderBudget =
            memoryUsageAfterMakeResident - videoMemorySegmentInfo->budget;
        uint64_t sizeEvicted = 0;
        while (sizeEvicted < sizeNeededToBeUnderBudget) {
            Heap* heap = nullptr;
            ReturnIfFailed(EvictHeap(videoMemorySegmentInfo, &heap));

            // If no heap was returned, then nothing more can be evicted.
            if (heap == nullptr) {
                break;
            }

            sizeEvicted += heap->GetSize();
            resourcesToEvict.push_back(heap->GetPageable());
        }

        if (resourcesToEvict.size() > 0) {
            ReturnIfFailed(mDevice->Evict(resourcesToEvict.size(), resourcesToEvict.data()));
        }

        if (sizeEvictedOut != nullptr) {
            *sizeEvictedOut = sizeEvicted;
        }
        return S_OK;
    }

    // Given a list of heaps that are pending usage, this function will estimate memory needed,
    // evict resources until enough space is available, then make resident any heaps scheduled for
    // usage.
    HRESULT ResidencyManager::ExecuteCommandLists(ID3D12CommandQueue* d3d12Queue,
                                                  ID3D12CommandList** d3d12CommandLists,
                                                  ResidencySet** residencySets,
                                                  uint32_t count) {
        // TODO: support multiple command lists.
        ASSERT(count == 1);
        ID3D12CommandList* commandList = d3d12CommandLists[0];
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
            hr = MakeResident(mVideoMemoryInfo.localVideoMemorySegment.dxgiMemorySegmentGroup,
                              localSizeToMakeResident, localHeapsToMakeResident.size(),
                              localHeapsToMakeResident.data());
        } else if (nonLocalSizeToMakeResident > 0) {
            ASSERT(!mIsUMA);
            hr = MakeResident(mVideoMemoryInfo.nonLocalVideoMemorySegment.dxgiMemorySegmentGroup,
                              nonLocalSizeToMakeResident, nonLocalHeapsToMakeResident.size(),
                              nonLocalHeapsToMakeResident.data());
        }

        d3d12Queue->ExecuteCommandLists(1, &commandList);

        if (SUCCEEDED(hr)) {
            hr = mFence->Signal(d3d12Queue);
        }

        return hr;
    }

    HRESULT ResidencyManager::MakeResident(const DXGI_MEMORY_SEGMENT_GROUP dxgiMemorySegmentGroup,
                                           uint64_t sizeToMakeResident,
                                           uint64_t numberOfObjectsToMakeResident,
                                           ID3D12Pageable** allocations) {
        Evict(sizeToMakeResident, dxgiMemorySegmentGroup, nullptr);

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
            Evict(kDefaultResidentResourceEvictSize, dxgiMemorySegmentGroup, &sizeEvicted);

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
        // Heap already exists in the cache.
        if (heap->IsInList()) {
            return E_INVALIDARG;
        }

        GetVideoMemorySegmentInfo(heap->GetMemorySegmentGroup())->lruCache.Append(heap);

        return S_OK;
    }
}}  // namespace gpgmm::d3d12
