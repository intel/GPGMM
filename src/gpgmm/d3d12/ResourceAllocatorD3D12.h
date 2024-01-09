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
                                               IResourceAllocator* pResourceAllocator,
                                               IResourceAllocator** ppResourceAllocatorOut);

        static HRESULT CreateResourceAllocator(const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
                                               IResourceAllocator* pResourceAllocator,
                                               IResourceAllocator** ppResourceAllocatorOut);

        ~ResourceAllocator() override;

        // IResourceAllocator interface
        HRESULT CreateResource(const RESOURCE_ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialResourceState,
                               const D3D12_CLEAR_VALUE* pClearValue,
                               IResourceAllocation** ppResourceAllocationOut) override;
        HRESULT CreateResource(const RESOURCE_ALLOCATION_DESC& allocationDescriptor,
                               ID3D12Resource* pCommittedResource,
                               IResourceAllocation** ppResourceAllocationOut) override;
        HRESULT ReleaseResourceHeaps(uint64_t bytesToRelease, uint64_t* pBytesReleased) override;
        HRESULT QueryStats(RESOURCE_ALLOCATOR_STATS* pResourceAllocatorStats) override;
        HRESULT CheckFeatureSupport(RESOURCE_ALLOCATOR_FEATURE feature,
                                    void* pFeatureSupportData,
                                    uint32_t featureSupportDataSize) const override;

        DEFINE_UNKNOWN_OVERRIDES()

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

        ID3D12Device* GetDevice() const;
        IDXGIAdapter* GetAdapter() const;
        IResidencyManager* GetResidencyManager() const;

      private:
        friend BufferAllocator;
        friend ResourceAllocation;

        ResourceAllocator(const RESOURCE_ALLOCATOR_DESC& descriptor,
                          ID3D12Device* pDevice,
                          IDXGIAdapter* pAdapter,
                          ResidencyManager* pResidencyManager,
                          std::unique_ptr<Caps> caps);

        ResourceAllocator(const RESOURCE_ALLOCATOR_DESC& descriptor,
                          ResourceAllocator* allocator,
                          std::unique_ptr<Caps> caps);

        void DeleteThis() override;

        template <typename CreateResourceFn>
        MaybeError TryAllocateResource(MemoryAllocatorBase* allocator,
                                       const MemoryAllocationRequest& request,
                                       CreateResourceFn&& createResourceFn);

        MaybeError CreateResourceInternal(const RESOURCE_ALLOCATION_DESC& allocationDescriptor,
                                          const D3D12_RESOURCE_ALLOCATION_INFO& resourceInfo,
                                          const D3D12_RESOURCE_DESC& resourceDescriptor,
                                          D3D12_RESOURCE_STATES initialResourceState,
                                          const D3D12_CLEAR_VALUE* clearValue,
                                          ResourceAllocation** ppResourceAllocationOut);

        ScopedRef<MemoryAllocatorBase> CreateSmallBufferAllocator(
            const RESOURCE_ALLOCATOR_DESC& descriptor,
            D3D12_HEAP_FLAGS heapFlags,
            const D3D12_HEAP_PROPERTIES& heapProperties,
            const HEAP_ALLOCATION_INFO& heapInfo,
            D3D12_RESOURCE_FLAGS resourceFlags,
            D3D12_RESOURCE_STATES initialResourceState);

        ScopedRef<MemoryAllocatorBase> CreatePoolAllocator(
            RESOURCE_ALLOCATION_ALGORITHM algorithm,
            const HEAP_ALLOCATION_INFO& heapInfo,
            bool isAlwaysOnDemand,
            ScopedRef<MemoryAllocatorBase> underlyingAllocator);

        ScopedRef<MemoryAllocatorBase> CreateSubAllocator(
            RESOURCE_ALLOCATION_ALGORITHM algorithm,
            const HEAP_ALLOCATION_INFO& heapInfo,
            float memoryFragmentationLimit,
            float memoryGrowthFactor,
            bool isPrefetchAllowed,
            ScopedRef<MemoryAllocatorBase> underlyingAllocator);

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
                                        ResidencyHeap** resourceHeapOut);

        HRESULT ReleaseResourceHeapsInternal(uint64_t bytesToRelease, uint64_t* pBytesReleased);

        HRESULT ReportLiveDeviceObjects() const;

        bool IsCreateHeapNotResidentEnabled() const;
        bool IsResidencyEnabled() const;

        D3D12_RESOURCE_ALLOCATION_INFO GetResourceAllocationInfo(
            const D3D12_RESOURCE_DESC& resourceDescriptor) const;

        // MemoryAllocatorBase interface
        void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) override;

        MemoryAllocatorStats GetStats() const override;

        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(IResourceAllocator)

        ID3D12Device* mDevice = nullptr;
        IDXGIAdapter* mAdapter = nullptr;
        ComPtr<ResidencyManager> mResidencyManager;

        std::unique_ptr<Caps> mCaps;

        const D3D12_RESOURCE_HEAP_TIER mResourceHeapTier;
        const D3D12_RESOURCE_FLAGS mExtraRequiredResourceFlags;
        const bool mIsAlwaysCommitted;
        const bool mIsAlwaysCreatedInBudget;
        const bool mFlushEventBuffersOnDestruct;
        const bool mUseDetailedTimingEvents;
        const bool mIsCustomHeapsEnabled;
        const bool mIsCreateNotResidentEnabled;
        const uint64_t mMaxResourceHeapSize;
        const bool mIsNeverOverAllocateEnabled = false;
        const uint64_t mReleaseSizeInBytes;

        static constexpr uint64_t kNumOfResourceHeapTypes = 12u;

        std::array<ScopedRef<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mPooledOrNonPooledHeapAllocator;
        std::array<ScopedRef<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mMSAAPooledOrNonPooledHeapAllocator;

        std::array<ScopedRef<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mDedicatedResourceAllocatorOfType;
        std::array<ScopedRef<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mResourceAllocatorOfType;

        std::array<ScopedRef<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mMSAADedicatedResourceAllocatorOfType;
        std::array<ScopedRef<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mMSAAResourceAllocatorOfType;

        std::array<ScopedRef<MemoryAllocatorBase>, kNumOfResourceHeapTypes>
            mSmallBufferAllocatorOfType;

        ScopedRef<ResourceAllocationTrackingAllocator> mTrackingAllocator;
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
