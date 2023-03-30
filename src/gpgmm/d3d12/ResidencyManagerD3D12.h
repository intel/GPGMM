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

#ifndef GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
#define GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_

#include "gpgmm/common/Object.h"
#include "gpgmm/d3d12/DebugObjectD3D12.h"
#include "gpgmm/utils/EnumFlags.h"
#include "gpgmm/utils/LinkedList.h"

#include <gpgmm_d3d12.h>

#include <memory>
#include <mutex>

namespace gpgmm {
    class TaskScheduler;
}  // namespace gpgmm

namespace gpgmm::d3d12 {

    class BudgetUpdateTask;
    class BudgetUpdateEvent;
    class Caps;
    class Fence;
    class Heap;
    class ResourceAllocator;
    class ResourceHeapAllocator;

    class ResidencyManager final : public DebugObject, public IResidencyManager, public ObjectBase {
      public:
        static HRESULT CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                              IResidencyManager** ppResidencyManagerOut);

        ~ResidencyManager() override;

        // IResidencyManager interface
        HRESULT LockHeap(IHeap* pHeap) override;
        HRESULT UnlockHeap(IHeap* pHeap) override;
        HRESULT ExecuteCommandLists(ID3D12CommandQueue* pQueue,
                                    ID3D12CommandList* const* ppCommandLists,
                                    IResidencyList* const* ppResidencyLists,
                                    uint32_t count) override;

        HRESULT SetVideoMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                          uint64_t availableForReservation,
                                          uint64_t* pCurrentReservationOut = nullptr) override;

        HRESULT QueryVideoMemoryInfo(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                     DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfoOut) override;
        HRESULT SetResidencyState(IHeap* pHeap, const RESIDENCY_STATUS& state) override;

        HRESULT QueryStats(RESIDENCY_MANAGER_STATS* pResidencyManagerStats) override;

        DEFINE_UNKNOWN_OVERRIDES()

      private:
        friend Heap;
        friend ResourceAllocator;
        friend ResourceHeapAllocator;

        ResidencyManager(const RESIDENCY_DESC& descriptor, std::unique_ptr<Caps> caps);

        HRESULT EnsureInBudget(uint64_t bytesToEvict,
                               const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        HRESULT EvictInternal(uint64_t bytesToEvict,
                              const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                              uint64_t* bytesEvictedOut = nullptr);

        HRESULT InsertHeap(Heap* heap);

        HRESULT InsertHeapInternal(Heap* heap);

        HRESULT QueryStatsInternal(RESIDENCY_MANAGER_STATS* pResidencyManagerStats);

        friend BudgetUpdateTask;
        HRESULT UpdateMemorySegments();

        bool IsUMA() const;

        // ObjectBase interface
        const char* GetTypename() const override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

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

        void ReportSegmentInfoForTesting(DXGI_MEMORY_SEGMENT_GROUP segmentGroup);

        HRESULT EnsureResidencyFenceExists();

        ID3D12Device* mDevice = nullptr;
        IDXGIAdapter3* mAdapter = nullptr;

        const float mMaxPctOfVideoMemoryToBudget;
        const float mMinPctOfBudgetToReserve;
        const bool mIsBudgetRestricted;
        const uint64_t mEvictSizeInBytes;
        const bool mIsUMA;
        const bool mFlushEventBuffersOnDestruct;
        const uint64_t mInitialFenceValue;

        mutable std::mutex mMutex;

        std::unique_ptr<Fence> mResidencyFence;

        VideoMemorySegment mLocalVideoMemorySegment;
        VideoMemorySegment mNonLocalVideoMemorySegment;
        RESIDENCY_MANAGER_STATS mStats = {};

        std::shared_ptr<BudgetUpdateEvent> mBudgetNotificationUpdateEvent;
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
