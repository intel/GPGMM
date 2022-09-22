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

#ifndef INCLUDE_MIN_GPGMM_D3D12_H_
#define INCLUDE_MIN_GPGMM_D3D12_H_

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
// - GPGMM_D3D12_HEADERS_ALREADY_INCLUDED: D3D12 platform headers will be already included before
// this header and does not need to be re-included.
// - GPGMM_WINDOWS_HEADERS_ALREADY_INCLUDED: Windows.h will be already included before this header
// and does not need to be re-included.
// - GPGMM_REFCOUNT_TYPE <type>: Allows a user-defined ref-count type to be used instead of
// the STL-provided one. The increment, decrement, and equals operator must be defined.
#ifndef GPGMM_D3D12_HEADERS_ALREADY_INCLUDED
#    include <d3d12.h>
#    include <dxgi1_4.h>
#    include <wrl.h>
#endif

#ifndef GPGMM_WINDOWS_HEADERS_ALREADY_INCLUDED
#    include <windows.h>  // for DEFINE_ENUM_FLAG_OPERATORS
#endif

#if !defined(GPGMM_REFCOUNT_TYPE)
#    include <atomic>
#endif

#ifndef GPGMM_REFCOUNT_TYPE
#    define GPGMM_REFCOUNT_TYPE std::atomic<uint64_t>
#endif

#include <functional>
#include <string>

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

    enum RESIDENCY_STATUS {
        RESIDENCY_UNKNOWN = 0,
        PENDING_RESIDENCY = 1,
        CURRENT_RESIDENT = 2,
    };

    struct HEAP_INFO {
        bool IsLocked;
        RESIDENCY_STATUS Status;
    };

    enum HEAPS_FLAGS {
        HEAPS_FLAG_NONE = 0x0,
        HEAP_FLAG_ALWAYS_IN_BUDGET = 0x1,
    };

    DEFINE_ENUM_FLAG_OPERATORS(HEAPS_FLAGS)

    struct HEAP_DESC {
        uint64_t SizeInBytes;
        uint64_t Alignment;
        HEAPS_FLAGS Flags;
        DXGI_MEMORY_SEGMENT_GROUP MemorySegmentGroup;
        LPCWSTR DebugName;
    };

    using CreateHeapFn = std::function<HRESULT(ID3D12Pageable** ppPageableOut)>;

    class ResidencyManager;
    class ResourceAllocator;

    class Heap final : public MemoryBase, public IUnknownImpl {
      public:
        static HRESULT CreateHeap(const HEAP_DESC& descriptor,
                                  ResidencyManager* const pResidencyManager,
                                  CreateHeapFn&& createHeapFn,
                                  Heap** ppHeapOut);

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        HEAP_INFO GetInfo() const;

      private:
        Heap(Microsoft::WRL::ComPtr<ID3D12Pageable> pageable,
             const HEAP_DESC& descriptor,
             bool isResidencyDisabled);

        Microsoft::WRL::ComPtr<ID3D12Pageable> mPageable;
    };

    class ResidencyList final {
      public:
        ResidencyList();

        HRESULT Add(Heap* pHeap);
        HRESULT Reset();
    };

    enum EVENT_RECORD_FLAGS {
        EVENT_RECORD_FLAG_NONE = 0x0,
        EVENT_RECORD_FLAG_API_OBJECTS = 0x1,
        EVENT_RECORD_FLAG_API_CALLS = 0x2,
        EVENT_RECORD_FLAG_API_TIMINGS = 0x4,
        EVENT_RECORD_FLAG_COUNTERS = 0x8,
        EVENT_RECORD_FLAG_CAPTURE = 0x3,
        EVENT_RECORD_FLAG_ALL_EVENTS = 0xFF,
    };

    DEFINE_ENUM_FLAG_OPERATORS(EVENT_RECORD_FLAGS)

    enum EVENT_RECORD_SCOPE {
        EVENT_RECORD_SCOPE_PER_PROCESS = 0,
        EVENT_RECORD_SCOPE_PER_INSTANCE = 1,
    };

    struct EVENT_RECORD_OPTIONS {
        EVENT_RECORD_FLAGS Flags;
        D3D12_MESSAGE_SEVERITY MinMessageLevel;
        EVENT_RECORD_SCOPE EventScope;
        bool UseDetailedTimingEvents;
        std::string TraceFile;
    };

    enum RESIDENCY_FLAGS {
        RESIDENCY_FLAG_NONE = 0x0,
        RESIDENCY_FLAG_NEVER_UPDATE_BUDGET_ON_WORKER_THREAD = 0x1,
    };

    DEFINE_ENUM_FLAG_OPERATORS(RESIDENCY_FLAGS)

    struct RESIDENCY_DESC {
        Microsoft::WRL::ComPtr<ID3D12Device> Device;
        Microsoft::WRL::ComPtr<IDXGIAdapter3> Adapter;
        bool IsUMA;
        RESIDENCY_FLAGS Flags;
        D3D12_MESSAGE_SEVERITY MinLogLevel;
        EVENT_RECORD_OPTIONS RecordOptions;
        float MaxPctOfVideoMemoryToBudget;
        float MinPctOfBudgetToReserve;
        uint64_t MaxBudgetInBytes;
        uint64_t EvictSizeInBytes;
        uint64_t InitialFenceValue;
    };

    struct RESIDENCY_INFO {
        uint64_t CurrentMemoryUsage;
        uint64_t CurrentMemoryCount;
    };

    class ResidencyManager final : public IUnknownImpl {
      public:
        static HRESULT CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                              ResidencyManager** ppResidencyManagerOut);

        ~ResidencyManager() override;

        HRESULT LockHeap(Heap* pHeap);
        HRESULT UnlockHeap(Heap* pHeap);
        HRESULT ExecuteCommandLists(ID3D12CommandQueue* pQueue,
                                    ID3D12CommandList* const* ppCommandLists,
                                    ResidencyList* const* ppResidencyLists,
                                    uint32_t count);
        HRESULT SetVideoMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                          uint64_t availableForReservation,
                                          uint64_t* pCurrentReservationOut = nullptr);
        HRESULT QueryVideoMemoryInfo(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                     DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfoOut);
        RESIDENCY_INFO GetInfo() const;

      private:
        ResidencyManager(const RESIDENCY_DESC& descriptor);

        Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
        Microsoft::WRL::ComPtr<IDXGIAdapter3> mAdapter;
    };

    struct RESOURCE_ALLOCATION_DESC {
        uint64_t SizeInBytes;
        uint64_t HeapOffset;
        uint64_t OffsetFromResource;
        AllocationMethod Method;
        LPCWSTR DebugName;
    };

    struct RESOURCE_ALLOCATION_INFO {
        uint64_t SizeInBytes;
        uint64_t Alignment;
    };

    class ResourceAllocation final : public MemoryAllocation, public IUnknownImpl {
      public:
        HRESULT Map(uint32_t subresource = 0,
                    const D3D12_RANGE* pReadRange = nullptr,
                    void** ppDataOut = nullptr);
        void Unmap(uint32_t subresource = 0, const D3D12_RANGE* pWrittenRange = nullptr);
        ID3D12Resource* GetResource() const;
        D3D12_GPU_VIRTUAL_ADDRESS GetGPUVirtualAddress() const;
        uint64_t GetOffsetFromResource() const;
        RESOURCE_ALLOCATION_INFO GetInfo() const;
        Heap* GetMemory() const;

      private:
        friend ResourceAllocator;

        ResourceAllocation(const RESOURCE_ALLOCATION_DESC& desc,
                           MemoryAllocator* allocator,
                           Heap* resourceHeap,
                           Microsoft::WRL::ComPtr<ID3D12Resource> resource);

        void DeleteThis() override;

        Microsoft::WRL::ComPtr<ID3D12Resource> mResource;
    };

    enum ALLOCATOR_FLAGS {
        ALLOCATOR_FLAG_NONE = 0x0,
        ALLOCATOR_FLAG_ALWAYS_COMMITED = 0x1,
        ALLOCATOR_FLAG_ALWAYS_IN_BUDGET = 0x2,
        ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH = 0x4,
        ALLOCATOR_FLAG_ALWAYS_ON_DEMAND = 0x8,
        ALLOCATOR_FLAG_DISABLE_CUSTOM_HEAPS = 0x10,
        ALLOCATOR_FLAG_NEVER_LEAK_MEMORY = 0x20,
    };

    DEFINE_ENUM_FLAG_OPERATORS(ALLOCATOR_FLAGS)

    enum ALLOCATOR_ALGORITHM {
        ALLOCATOR_ALGORITHM_DEFAULT = 0,
        ALLOCATOR_ALGORITHM_SLAB = 1,
        ALLOCATOR_ALGORITHM_BUDDY_SYSTEM = 2,
        ALLOCATOR_ALGORITHM_FIXED_POOL = 3,
        ALLOCATOR_ALGORITHM_SEGMENTED_POOL = 4,
        ALLOCATOR_ALGORITHM_DEDICATED = 5,
    };

    DEFINE_ENUM_FLAG_OPERATORS(ALLOCATOR_ALGORITHM)

    struct ALLOCATOR_DESC {
        Microsoft::WRL::ComPtr<ID3D12Device> Device;
        Microsoft::WRL::ComPtr<IDXGIAdapter> Adapter;
        ALLOCATOR_FLAGS Flags;
        D3D12_MESSAGE_SEVERITY MinLogLevel;
        EVENT_RECORD_OPTIONS RecordOptions;
        D3D12_RESOURCE_HEAP_TIER ResourceHeapTier;
        ALLOCATOR_ALGORITHM SubAllocationAlgorithm;
        ALLOCATOR_ALGORITHM PoolAlgorithm;
        uint64_t PreferredResourceHeapSize;
        uint64_t MaxResourceHeapSize;
        double MemoryFragmentationLimit;
        double MemoryGrowthFactor;
    };

    enum ALLOCATION_FLAGS {
        ALLOCATION_FLAG_NONE = 0x0,
        ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY = 0x1,
        ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE = 0x2,
        ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY = 0x4,
        ALLOCATION_FLAG_ALWAYS_PREFETCH_MEMORY = 0x8,
        ALLOCATION_FLAG_ALWAYS_CACHE_SIZE = 0x10,
        ALLOCATION_FLAG_ALWAYS_ATTRIBUTE_HEAPS = 0x20,
        ALLOCATION_FLAG_NEVER_FALLBACK = 0x40,
    };

    DEFINE_ENUM_FLAG_OPERATORS(ALLOCATION_FLAGS)

    struct ALLOCATION_DESC {
        ALLOCATION_FLAGS Flags;
        D3D12_HEAP_TYPE HeapType;
        D3D12_HEAP_FLAGS ExtraRequiredHeapFlags;
        uint64_t RequireResourceHeapPadding;
        LPCWSTR DebugName;
    };

    enum ALLOCATOR_FEATURE {
        ALLOCATOR_FEATURE_RESOURCE_ALLOCATION_SUPPORT,
    };

    using RESOURCE_ALLOCATOR_INFO = MemoryAllocatorInfo;

    class ResourceAllocator final : public MemoryAllocator, public IUnknownImpl {
      public:
        static HRESULT CreateAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                       ResourceAllocator** ppResourceAllocatorOut,
                                       ResidencyManager** ppResidencyManagerOut = nullptr);

        static HRESULT CreateAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                       ResidencyManager* pResidencyManager,
                                       ResourceAllocator** ppResourceAllocatorOut);

        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialResourceState,
                               const D3D12_CLEAR_VALUE* pClearValue,
                               ResourceAllocation** ppResourceAllocationOut);

        HRESULT CreateResource(Microsoft::WRL::ComPtr<ID3D12Resource> committedResource,
                               ResourceAllocation** ppResourceAllocationOut);

        uint64_t ReleaseMemory(uint64_t bytesToRelease) override;

        RESOURCE_ALLOCATOR_INFO GetInfo() const override;

        HRESULT CheckFeatureSupport(ALLOCATOR_FEATURE feature,
                                    void* pFeatureSupportData,
                                    uint32_t featureSupportDataSize) const;

      private:
        ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                          Microsoft::WRL::ComPtr<ResidencyManager> residencyManager);

        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
        Microsoft::WRL::ComPtr<ResidencyManager> mResidencyManager;
    };

}  // namespace gpgmm::d3d12

#endif  // INCLUDE_MIN_GPGMM_D3D12_H_
