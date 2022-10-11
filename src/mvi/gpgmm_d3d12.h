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

namespace gpgmm::d3d12 {

    class IUnknownImpl : public IUnknown {
      public:
        IUnknownImpl();
        virtual ~IUnknownImpl();

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

      protected:
        virtual void DeleteThis();

      private:
        GPGMM_REFCOUNT_TYPE mRefCount;
    };

    class Heap final : public MemoryBase, public IUnknownImpl, public IHeap {
      public:
        static HRESULT CreateHeap(const HEAP_DESC& descriptor,
                                  IResidencyManager* const pResidencyManager,
                                  CreateHeapFn&& createHeapFn,
                                  IHeap** ppHeapOut);

        // IHeap interface
        HEAP_INFO GetInfo() const override;
        bool IsInResidencyLRUCacheForTesting() const override;
        bool IsResidencyLockedForTesting() const override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        Heap(Microsoft::WRL::ComPtr<ID3D12Pageable> pageable,
             const HEAP_DESC& descriptor,
             bool isResidencyDisabled);

        Microsoft::WRL::ComPtr<ID3D12Pageable> mPageable;
    };

    class ResidencyList final : public IResidencyList, public IUnknownImpl {
      public:
        ResidencyList();

        HRESULT Add(IHeap* pHeap) override;
        HRESULT Reset() override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;
    };

    class ResidencyManager final : public IUnknownImpl, public IResidencyManager {
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
        RESIDENCY_STATS GetStats() const override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

      private:
        ResidencyManager(const RESIDENCY_DESC& descriptor);

        Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
        Microsoft::WRL::ComPtr<IDXGIAdapter3> mAdapter;
    };

    class ResourceAllocator;

    class ResourceAllocation final : public MemoryAllocation,
                                     public IUnknownImpl,
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
        IHeap* GetMemory() const override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        friend ResourceAllocator;

        ResourceAllocation(const RESOURCE_ALLOCATION_DESC& desc,
                           MemoryAllocator* allocator,
                           Heap* resourceHeap,
                           Microsoft::WRL::ComPtr<ID3D12Resource> resource);

        void DeleteThis() override;

        Microsoft::WRL::ComPtr<ID3D12Resource> mResource;
    };

    class ResourceAllocator final : public MemoryAllocator,
                                    public IUnknownImpl,
                                    public IResourceAllocator {
      public:
        static HRESULT CreateResourceAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                               IResourceAllocator** ppResourceAllocatorOut,
                                               IResidencyManager** ppResidencyManagerOut);

        static HRESULT CreateResourceAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                               IResidencyManager* pResidencyManager,
                                               IResourceAllocator** ppResourceAllocatorOut);

        // IResourceAllocator interface
        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialResourceState,
                               const D3D12_CLEAR_VALUE* pClearValue,
                               IResourceAllocation** ppResourceAllocationOut) override;
        HRESULT CreateResource(Microsoft::WRL::ComPtr<ID3D12Resource> committedResource,
                               IResourceAllocation** ppResourceAllocationOut) override;
        uint64_t ReleaseMemory(uint64_t bytesToRelease) override;
        RESOURCE_ALLOCATOR_STATS GetStats() const override;
        HRESULT CheckFeatureSupport(ALLOCATOR_FEATURE feature,
                                    void* pFeatureSupportData,
                                    uint32_t featureSupportDataSize) const override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

      private:
        ResourceAllocator(const ALLOCATOR_DESC& descriptor, IResidencyManager* pResidencyManager);

        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
        Microsoft::WRL::ComPtr<IResidencyManager> mResidencyManager;
    };

}  // namespace gpgmm::d3d12

#endif  // MVI_GPGMM_D3D12_H_
