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

#ifndef SRC_GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
#define SRC_GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_

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
    class ResidencyHeap;
    class ResourceAllocator;
    class ResourceHeapAllocator;

    class ResidencyManager final : public DebugObject, public IResidencyManager, public ObjectBase {
      public:
        static HRESULT CreateResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                              ID3D12Device* pDevice,
                                              IUnknown* pAdapter,
                                              IResidencyManager** ppResidencyManagerOut);

        ~ResidencyManager() override;

        // IResidencyManager interface
        HRESULT ExecuteCommandLists(ID3D12CommandQueue* pQueue,
                                    ID3D12CommandList* const* ppCommandLists,
                                    IResidencyList* const* ppResidencyLists,
                                    uint32_t count) override;

        HRESULT SetMemoryReservation(const RESIDENCY_HEAP_SEGMENT& heapSegment,
                                     uint64_t availableForReservation,
                                     uint64_t* pCurrentReservationOut = nullptr) override;

        HRESULT QueryMemoryInfo(const RESIDENCY_HEAP_SEGMENT& heapSegment,
                                RESIDENCY_MEMORY_INFO* pMemoryInfoOut) override;
        HRESULT SetResidencyStatus(IResidencyHeap* pHeap,
                                   const RESIDENCY_HEAP_STATUS& newStatus) override;

        HRESULT QueryStats(RESIDENCY_MANAGER_STATS* pResidencyManagerStats) override;

        DEFINE_UNKNOWN_OVERRIDES()

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

        HRESULT LockHeap(ResidencyHeap* pHeap);
        HRESULT UnlockHeap(ResidencyHeap* pHeap);

      private:
        friend ResidencyHeap;
        friend ResourceAllocator;
        friend ResourceHeapAllocator;

        ResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                         ID3D12Device* pDevice,
                         IDXGIAdapter3* pAdapter,
                         std::unique_ptr<Caps> caps);

        // Unknown interface
        void DeleteThis() override;

        HRESULT EvictInternal(uint64_t bytesToEvict,
                              const RESIDENCY_HEAP_SEGMENT& heapSegment,
                              uint64_t* bytesEvictedOut = nullptr);

        HRESULT InsertHeap(ResidencyHeap* heap);

        HRESULT InsertHeapInternal(ResidencyHeap* heap);

        HRESULT QueryStatsInternal(RESIDENCY_MANAGER_STATS* pResidencyManagerStats);

        friend BudgetUpdateTask;
        HRESULT UpdateMemorySegments();

        bool IsUMA() const;

        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(IResidencyManager)

        using LRUCache = LinkedList<ResidencyHeap>;

        struct MemorySegment {
            LRUCache cache = {};
            RESIDENCY_MEMORY_INFO Info = {};
        };

        HRESULT MakeResident(const RESIDENCY_HEAP_SEGMENT heapSegment,
                             uint64_t sizeToMakeResident,
                             uint32_t numberOfObjectsToMakeResident,
                             ID3D12Pageable** allocations);

        LRUCache* GetMemorySegmentCache(const RESIDENCY_HEAP_SEGMENT& heapSegment);

        RESIDENCY_MEMORY_INFO* GetMemoryInfo(const RESIDENCY_HEAP_SEGMENT& heapSegment);

        HRESULT UpdateMemorySegmentInternal(const RESIDENCY_HEAP_SEGMENT& heapSegment);

        HRESULT StartBudgetNotificationUpdates();
        void StopBudgetNotificationUpdates();

        bool IsBudgetNotificationUpdatesDisabled() const;

        void ReportSegmentInfoForTesting(RESIDENCY_HEAP_SEGMENT segmentGroup);

        HRESULT EnsureResidencyFenceExists();

        ID3D12Device* mDevice = nullptr;
        IDXGIAdapter3* mAdapter = nullptr;

        const float mMaxPctOfMemoryToBudget;
        const float mMinPctOfBudgetToReserve;
        const bool mIsBudgetRestricted;
        const uint64_t mEvictSizeInBytes;
        const bool mIsUMA;
        const bool mFlushEventBuffersOnDestruct;
        const uint64_t mInitialFenceValue;
        const bool mIsAlwaysInBudget;

        mutable std::mutex mMutex;

        std::unique_ptr<Fence> mResidencyFence;

        MemorySegment mLocalMemorySegment;
        MemorySegment mNonLocalMemorySegment;
        RESIDENCY_MANAGER_STATS mStats = {};

        std::shared_ptr<BudgetUpdateEvent> mBudgetNotificationUpdateEvent;
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
