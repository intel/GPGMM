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

#ifndef GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
#define GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_

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
    class Heap;
    class DebugResourceAllocator;
    class ResidencyManager;
    class ResourceAllocation;

    class ResourceAllocator final : public DebugObject,
                                    public IResourceAllocator,
                                    public MemoryAllocator {
      public:
        static HRESULT CreateResourceAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                               ID3D12Device* pDevice,
                                               IDXGIAdapter* pAdapter,
                                               IResourceAllocator** ppResourceAllocatorOut,
                                               IResidencyManager** ppResidencyManagerOut);

        static HRESULT CreateResourceAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
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

        // ObjectBase interface
        const char* GetTypename() const override;

        HRESULT CreateResourceInternal(const ALLOCATION_DESC& allocationDescriptor,
                                       const D3D12_RESOURCE_DESC& resourceDescriptor,
                                       D3D12_RESOURCE_STATES initialResourceState,
                                       const D3D12_CLEAR_VALUE* clearValue,
                                       IResourceAllocation** ppResourceAllocationOut);

        ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                          ID3D12Device* pDevice,
                          ResidencyManager* pResidencyManager,
                          std::unique_ptr<Caps> caps);

        std::unique_ptr<MemoryAllocator> CreateResourceAllocator(
            const ALLOCATOR_DESC& descriptor,
            D3D12_HEAP_FLAGS heapFlags,
            const D3D12_HEAP_PROPERTIES& heapProperties,
            uint64_t heapAlignment);

        std::unique_ptr<MemoryAllocator> CreateSmallBufferAllocator(
            const ALLOCATOR_DESC& descriptor,
            D3D12_HEAP_FLAGS heapFlags,
            const D3D12_HEAP_PROPERTIES& heapProperties,
            uint64_t heapAlignment,
            D3D12_RESOURCE_STATES initialResourceState);

        std::unique_ptr<MemoryAllocator> CreatePoolAllocator(
            ALLOCATOR_ALGORITHM algorithm,
            uint64_t memorySize,
            uint64_t memoryAlignment,
            bool isAlwaysOnDemand,
            std::unique_ptr<MemoryAllocator> underlyingAllocator);

        std::unique_ptr<MemoryAllocator> CreateSubAllocator(
            ALLOCATOR_ALGORITHM algorithm,
            uint64_t memorySize,
            uint64_t memoryAlignment,
            double memoryFragmentationLimit,
            double memoryGrowthFactor,
            bool isPrefetchAllowed,
            std::unique_ptr<MemoryAllocator> underlyingAllocator);

        HRESULT CreatePlacedResource(Heap* const resourceHeap,
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
                                        ID3D12Resource** commitedResourceOut,
                                        Heap** resourceHeapOut);

        HRESULT ReportLiveDeviceObjects() const;

        bool IsCreateHeapNotResident() const;
        bool IsResidencyEnabled() const;

        D3D12_RESOURCE_ALLOCATION_INFO GetResourceAllocationInfo(
            D3D12_RESOURCE_DESC& resourceDescriptor) const;

        // MemoryAllocator interface
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        HRESULT QueryStatsInternal(ALLOCATOR_STATS* pResourceAllocatorStats);

        ID3D12Device* mDevice = nullptr;
        ComPtr<ResidencyManager> mResidencyManager;

        std::unique_ptr<Caps> mCaps;

        const D3D12_RESOURCE_HEAP_TIER mResourceHeapTier;
        const bool mIsAlwaysCommitted;
        const bool mIsAlwaysCreatedInBudget;
        const bool mFlushEventBuffersOnDestruct;
        const bool mUseDetailedTimingEvents;
        const bool mIsCustomHeapsDisabled;
        const bool mIsAlwaysCreateResident;
        const uint64_t mMaxResourceHeapSize;

        static constexpr uint64_t kNumOfResourceHeapTypes = 12u;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mDedicatedResourceAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mResourceAllocatorOfType;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mMSAADedicatedResourceAllocatorOfType;
        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mMSAAResourceAllocatorOfType;

        std::array<std::unique_ptr<MemoryAllocator>, kNumOfResourceHeapTypes>
            mSmallBufferAllocatorOfType;

        std::unique_ptr<DebugResourceAllocator> mDebugAllocator;
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
