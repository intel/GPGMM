// Copyright 2019 The Dawn Authors
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

#ifndef SRC_GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
#define SRC_GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/d3d12/DebugObjectD3D12.h"
#include "gpgmm/utils/EnumFlags.h"

#include <gpgmm_d3d12.h>

#include <array>
#include <memory>
#include <string>

namespace gpgmm::d3d12 {

    class BufferAllocator;
    class Caps;
    class ResidencyHeap;
    class ResourceAllocationTrackingAllocator;
    class ResidencyManager;
    class ResourceAllocation;

    class ResourceAllocator final : public DebugObject,
                                    public IResourceAllocator,
                                    public MemoryAllocatorBase {
      public:
        static HRESULT CreateResourceAllocator(const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
                                               ID3D12Device* pDevice,
                                               IDXGIAdapter* pAdapter,
                                               IResourceAllocator** ppResourceAllocatorOut,
                                               IResidencyManager** ppResidencyManagerOut);

        static HRESULT CreateResourceAllocator(const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
                                               ID3D12Device* pDevice,
                                               IDXGIAdapter* pAdapter,
                                               IResidencyManager* pResidencyManager,
                                               IResourceAllocator** ppResourceAllocatorOut);

        ~ResourceAllocator() override;

        // IResourceAllocator interface
        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialResourceState,
                               const D3D12_CLEAR_VALUE* pClearValue,
                               IResourceAllocation** ppResourceAllocationOut) override;
        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               ID3D12Resource* pCommittedResource,
                               IResourceAllocation** ppResourceAllocationOut) override;
        HRESULT ReleaseResourceHeaps(uint64_t bytesToRelease, uint64_t* pBytesReleased) override;
        HRESULT QueryStats(ALLOCATOR_STATS* pResourceAllocatorStats) override;
        HRESULT CheckFeatureSupport(ALLOCATOR_FEATURE feature,
                                    void* pFeatureSupportData,
                                    uint32_t featureSupportDataSize) const override;

        DEFINE_UNKNOWN_OVERRIDES()

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        friend BufferAllocator;
        friend ResourceAllocation;

        ResourceAllocator(const RESOURCE_ALLOCATOR_DESC& descriptor,
                          ID3D12Device* pDevice,
                          ResidencyManager* pResidencyManager,
                          std::unique_ptr<Caps> caps);

        template <typename CreateResourceFn>
        HRESULT TryAllocateResource(MemoryAllocatorBase* allocator,
                                    const MemoryAllocationRequest& request,
                                    CreateResourceFn&& createResourceFn);

        HRESULT CreateResourceInternal(const ALLOCATION_DESC& allocationDescriptor,
                                       const D3D12_RESOURCE_DESC& resourceDescriptor,
                                       D3D12_RESOURCE_STATES initialResourceState,
                                       const D3D12_CLEAR_VALUE* clearValue,
                                       IResourceAllocation** ppResourceAllocationOut);

        std::unique_ptr<MemoryAllocatorBase> CreateResourceAllocator(
            const RESOURCE_ALLOCATOR_DESC& descriptor,
            D3D12_HEAP_FLAGS heapFlags,
            const D3D12_HEAP_PROPERTIES& heapProperties,
            uint64_t heapAlignment);

        std::unique_ptr<MemoryAllocatorBase> CreateSmallBufferAllocator(
            const RESOURCE_ALLOCATOR_DESC& descriptor,
            D3D12_HEAP_FLAGS heapFlags,
            const D3D12_HEAP_PROPERTIES& heapProperties,
            uint64_t heapAlignment,
            D3D12_RESOURCE_STATES initialResourceState);

        std::unique_ptr<MemoryAllocatorBase> CreatePoolAllocator(
            ALLOCATOR_ALGORITHM algorithm,
            uint64_t memorySize,
            uint64_t memoryAlignment,
            bool isAlwaysOnDemand,
            std::unique_ptr<MemoryAllocatorBase> underlyingAllocator);

        std::unique_ptr<MemoryAllocatorBase> CreateSubAllocator(
            ALLOCATOR_ALGORITHM algorithm,
            uint64_t memorySize,
            uint64_t memoryAlignment,
            float memoryFragmentationLimit,
            float memoryGrowthFactor,
            bool isPrefetchAllowed,
            std::unique_ptr<MemoryAllocatorBase> underlyingAllocator);

        HRESULT CreatePlacedResource(ResidencyHeap* const resourceHeap,
                                     uint64_t resourceOffset,
                                     const D3D12_RESOURCE_DESC* resourceDescriptor,
                                     const D3D12_CLEAR_VALUE* clearValue,
                                     D3D12_RESOURCE_STATES initialResourceState,
                                     ID3D12Resource** placedResourceOut);

        HRESULT CreateCommittedResource(D3D12_HEAP_PROPERTIES heapProperties,
                                        D3D12_HEAP_FLAGS heapFlags,
                                        const D3D12_RESOURCE_ALLOCATION_INFO& info,
                                        const D3D12_RESOURCE_DESC* resourceDescriptor,
                                        const D3D12_CLEAR_VALUE* clearValue,
                                        D3D12_RESOURCE_STATES initialResourceState,
                                        ID3D12Resource** committedResourceOut,
                                        ResidencyHeap** resourceHeapOut);

        HRESULT ReportLiveDeviceObjects() const;

        bool IsCreateHeapNotResidentEnabled() const;
        bool IsResidencyEnabled() const;

        D3D12_RESOURCE_ALLOCATION_INFO GetResourceAllocationInfo(
            D3D12_RESOURCE_DESC& resourceDescriptor) const;

        // MemoryAllocatorBase interface
        void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) override;

        HRESULT QueryStatsInternal(ALLOCATOR_STATS* pResourceAllocatorStats);

        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(IResourceAllocator)

        ID3D12Device* mDevice = nullptr;
        ComPtr<ResidencyManager> mResidencyManager;

        std::unique_ptr<Caps> mCaps;

        const D3D12_RESOURCE_HEAP_TIER mResourceHeapTier;
        const bool mIsAlwaysCommitted;
        const bool mIsAlwaysCreatedInBudget;
        const bool mFlushEventBuffersOnDestruct;
        const bool mUseDetailedTimingEvents;
        const bool mIsCustomHeapsEnabled;
        const bool mIsCreateNotResidentEnabled;
        const uint64_t mMaxResourceHeapSize;

        static constexpr uint64_t kNumOfResourceHeapTypes = 12u;

        std::array<std::unique_ptr<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mDedicatedResourceAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mResourceAllocatorOfType;

        std::array<std::unique_ptr<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mMSAADedicatedResourceAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mMSAAResourceAllocatorOfType;

        std::array<std::unique_ptr<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mSmallBufferAllocatorOfType;

        std::unique_ptr<ResourceAllocationTrackingAllocator> mTrackingAllocator;
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
