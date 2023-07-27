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

namespace gpgmm::d3d12 {

    class ResidencyManager;

    RESIDENCY_HEAP_FLAGS GetHeapFlags(D3D12_HEAP_FLAGS heapFlags, bool alwaysCreatedInBudget);

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

        ~ResidencyHeap() override;

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
        friend ResidencyManager;

        ResidencyHeap(ComPtr<ID3D12Pageable> pageable,
                      const RESIDENCY_HEAP_DESC& descriptor,
                      bool isResidencyDisabled);

        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(IHeap)

        HRESULT SetDebugNameImpl(LPCWSTR name) override;
        DXGI_MEMORY_SEGMENT_GROUP GetHeapSegment() const;

        // The residency manager must know the last fence value that any portion of the pageable was
        // submitted to be used so that we can ensure this pageable stays resident in memory at
        // least until that fence has completed.
        uint64_t GetLastUsedFenceValue() const;
        void SetLastUsedFenceValue(uint64_t fenceValue);

        void SetResidencyStatus(RESIDENCY_HEAP_STATUS newStatus);

        bool IsResidencyLocked() const;

        // Locks residency to ensure the heap cannot be evicted (ex. shader-visible descriptor
        // heaps or mapping resources).
        void AddResidencyLockRef();
        void ReleaseResidencyLock();

        ComPtr<ID3D12Pageable> mPageable;

        // mLastUsedFenceValue denotes the last time this pageable was submitted to the GPU.
        uint64_t mLastUsedFenceValue = 0;
        DXGI_MEMORY_SEGMENT_GROUP mHeapSegment;
        RefCounted mResidencyLock;
        bool mIsResidencyDisabled;
        RESIDENCY_HEAP_STATUS mState;
    };
}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_RESIDENCYHEAPD3D12_H_
