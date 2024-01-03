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

#ifndef SRC_GPGMM_D3D12_RESIDENCYHEAPD3D12_H_
#define SRC_GPGMM_D3D12_RESIDENCYHEAPD3D12_H_

#include "gpgmm/common/Memory.h"
#include "gpgmm/d3d12/DebugObjectD3D12.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/LinkedList.h"

#include <gpgmm_d3d12.h>

#include <mutex>

namespace gpgmm::d3d12 {

    class ResidencyManager;

    RESIDENCY_HEAP_FLAGS GetHeapFlags(D3D12_HEAP_FLAGS heapFlags, bool alwaysCreatedInBudget);

    // Thread-safe managed heap type for performing residency operations.
    // A ResidencyHeap wraps a ID3D12Pageable that can be temporarily or permanently made
    // resident and can be explicitly or implicitly (through allocation) created.
    class ResidencyHeap final : public MemoryBase,
                                public DebugObject,
                                public LinkNode<ResidencyHeap>,
                                public IResidencyHeap {
      public:
        static HRESULT CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                           IResidencyManager* const pResidencyManager,
                                           CreateHeapFn createHeapFn,
                                           void* pCreateHeapContext,
                                           IResidencyHeap** ppResidencyHeapOut);

        static HRESULT CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                           IResidencyManager* const pResidencyManager,
                                           ID3D12Pageable* pPageable,
                                           IResidencyHeap** ppResidencyHeapOut);

        ~ResidencyHeap() override;

        // IResidencyHeap interface
        RESIDENCY_HEAP_INFO GetInfo() const override;
        HRESULT Lock() override;
        HRESULT Unlock() override;
        HRESULT GetResidencyManager(IResidencyManager** ppResidencyManagerOut) const override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

        DXGI_MEMORY_SEGMENT_GROUP GetMemorySegment() const;

        uint64_t GetLastUsedFenceValue() const;
        void SetLastUsedFenceValue(uint64_t fenceValue);

        void SetResidencyStatus(RESIDENCY_HEAP_STATUS newStatus);

        bool IsResidencyLocked() const;

        // Locks residency to ensure the heap cannot be evicted (ex. shader-visible descriptor
        // heaps or mapping resources).
        void IncrementResidencyLockCount();
        void DecrementResidencyLockCount();

      private:
        ResidencyHeap(ComPtr<ResidencyManager> residencyManager,
                      ComPtr<ID3D12Pageable> pageable,
                      const RESIDENCY_HEAP_DESC& descriptor);

        // Unknown interface
        void DeleteThis() override;

        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(IHeap)

        // DebugObject interface
        HRESULT SetDebugNameImpl(LPCWSTR name) override;

        ComPtr<ResidencyManager> mResidencyManager;
        ComPtr<ID3D12Pageable> mPageable;

        DXGI_MEMORY_SEGMENT_GROUP mHeapSegment;
        RefCounted mResidencyLockCount;

        // Protects thread-access to the mutable members below.
        mutable std::mutex mMutex;
        RESIDENCY_HEAP_STATUS mState;

        // The residency manager must know the last fence value that any portion of the pageable was
        // submitted to be used so that we can ensure this pageable stays resident in memory at
        // least until that fence has completed.
        uint64_t mLastUsedFenceValue = 0;
    };
}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_RESIDENCYHEAPD3D12_H_
