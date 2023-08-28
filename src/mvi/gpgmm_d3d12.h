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

#ifndef MVI_GPGMM_D3D12_H_
#define MVI_GPGMM_D3D12_H_

// GPGMM minimum viable implementation (MVI).
//
// GPGMM MVI allows users to leverage GPGMM's portable GMM interface without
// requiring to build the full GPGMM implementation for incremental enabling during
// development.
//
// GPGMM MVI specifically,
// * Is not thread-safe.
// * Is functionally-equivelent to calling ID3D12Device::CreateCommittedResource.
// * Does not perform residency management or call ID3D12Device::MakeResident.
// * GMM functionality will otherwise "no-op" or pass-through.
//
// User should decide to define the following macros:
// - GPGMM_REFCOUNT_TYPE <type>: Allows a user-defined ref-count type to be used instead of
// the STL-provided one. The increment, decrement, and equals operator must be defined.
#if !defined(GPGMM_REFCOUNT_TYPE)
#    include <atomic>
#endif

#ifndef GPGMM_REFCOUNT_TYPE
#    define GPGMM_REFCOUNT_TYPE std::atomic<uint64_t>
#endif

#include <gpgmm_d3d12.h>

#include "gpgmm.h"

#include <wrl.h>  // for Microsoft::WRL::ComPtr

namespace gpgmm::d3d12 {

    class Unknown : public IUnknown {
      public:
        Unknown();
        virtual ~Unknown();

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

      protected:
        virtual void DeleteThis();

      private:
        GPGMM_REFCOUNT_TYPE mRefCount;
    };

    class ResidencyHeap final : public MemoryBase, public Unknown, public IResidencyHeap {
      public:
        static HRESULT CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                           IResidencyManager* const pResidencyManager,
                                           CreateHeapFn createHeapFn,
                                           void* context,
                                           IResidencyHeap** ppResidencyHeapOut);

        // IResidencyHeap interface
        RESIDENCY_HEAP_INFO GetInfo() const override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        ResidencyHeap(Microsoft::WRL::ComPtr<ID3D12Pageable> pageable,
                      const RESIDENCY_HEAP_DESC& descriptor,
                      bool isResidencyDisabled);

        Microsoft::WRL::ComPtr<ID3D12Pageable> mPageable;
    };

    class ResidencyList final : public IResidencyList, public Unknown {
      public:
        ResidencyList();

        HRESULT Add(IResidencyHeap* pHeap) override;
        HRESULT Reset() override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;
    };

    class ResidencyManager final : public Unknown, public IResidencyManager {
      public:
        static HRESULT CreateResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                                              ID3D12Device* pDevice,
                                              IDXGIAdapter3* pAdapter,
                                              IResidencyManager** ppResidencyManagerOut);

        ~ResidencyManager() override;

        // IResidencyManager interface
        HRESULT LockHeap(IResidencyHeap* pHeap) override;
        HRESULT UnlockHeap(IResidencyHeap* pHeap) override;
        HRESULT ExecuteCommandLists(ID3D12CommandQueue* pQueue,
                                    ID3D12CommandList* const* ppCommandLists,
                                    IResidencyList* const* ppResidencyLists,
                                    uint32_t count) override;
        HRESULT SetVideoMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& heapSegment,
                                          uint64_t availableForReservation,
                                          uint64_t* pCurrentReservationOut = nullptr) override;
        HRESULT QueryVideoMemoryInfo(const DXGI_MEMORY_SEGMENT_GROUP& heapSegment,
                                     DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfoOut) override;
        HRESULT SetResidencyStatus(IResidencyHeap* pHeap,
                                   const RESIDENCY_HEAP_STATUS& state) override;
        HRESULT QueryStats(RESIDENCY_MANAGER_STATS* pResidencyManagerStats) override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        ResidencyManager(const RESIDENCY_MANAGER_DESC& descriptor,
                         ID3D12Device* pDevice,
                         IDXGIAdapter3* pAdapter);

        Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
        Microsoft::WRL::ComPtr<IDXGIAdapter3> mAdapter;
    };

    class ResourceAllocator;

    class ResourceAllocation final : public MemoryAllocationBase,
                                     public Unknown,
                                     public IResourceAllocation {
      public:
        // IResourceAllocation interface
        HRESULT Map(uint32_t subresource = 0,
                    const D3D12_RANGE* pReadRange = nullptr,
                    void** ppDataOut = nullptr) override;
        void Unmap(uint32_t subresource = 0, const D3D12_RANGE* pWrittenRange = nullptr) override;
        ID3D12Resource* GetResource() const override;
        D3D12_GPU_VIRTUAL_ADDRESS GetGPUVirtualAddress() const override;
        uint64_t GetOffsetFromResource() const override;
        RESOURCE_ALLOCATION_INFO GetInfo() const override;
        IResidencyHeap* GetMemory() const override;
        HRESULT GetResidencyManager(IResidencyManager** ppResidencyManagerOut) const override;
        HRESULT GetResourceAllocator(IResourceAllocator** ppResourceAllocatorOut) const override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        friend ResourceAllocator;

        ResourceAllocation(MemoryAllocatorBase* allocator,
                           ResidencyHeap* resourceHeap,
                           Microsoft::WRL::ComPtr<ID3D12Resource> resource);

        void DeleteThis() override;

        Microsoft::WRL::ComPtr<ID3D12Resource> mResource;
    };

    class CreateCommittedResourceCallbackContext {
      public:
        CreateCommittedResourceCallbackContext(ID3D12Device* device,
                                               RESOURCE_ALLOCATION_DESC allocationDescriptor,
                                               Microsoft::WRL::ComPtr<ID3D12Resource> resource,
                                               const D3D12_RESOURCE_DESC* resourceDescriptor,
                                               const D3D12_CLEAR_VALUE* clearValue,
                                               D3D12_RESOURCE_STATES initialResourceState);
        static HRESULT CreateResidencyHeap(void* context, ID3D12Pageable** ppPageableOut);

      private:
        HRESULT CreateCommittedResource(ID3D12Pageable** ppPageableOut);

        ID3D12Device* mDevice;
        RESOURCE_ALLOCATION_DESC mAllocationDescriptor;
        const D3D12_CLEAR_VALUE* mClearValue;
        D3D12_RESOURCE_STATES mInitialResourceState;
        Microsoft::WRL::ComPtr<ID3D12Resource> mResource;
        const D3D12_RESOURCE_DESC* mResourceDescriptor;
    };

    class ResourceAllocator final : public MemoryAllocatorBase,
                                    public Unknown,
                                    public IResourceAllocator {
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

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        ResourceAllocator(const RESOURCE_ALLOCATOR_DESC& descriptor,
                          ID3D12Device* pDevice,
                          ResidencyManager* pResidencyManager);

        void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) override;

        Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
        Microsoft::WRL::ComPtr<ResidencyManager> mResidencyManager;
    };

}  // namespace gpgmm::d3d12

#endif  // MVI_GPGMM_D3D12_H_
