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

#ifndef GPGMM_D3D12_HEAPD3D12_H_
#define GPGMM_D3D12_HEAPD3D12_H_

#include "gpgmm/common/Memory.h"
#include "gpgmm/d3d12/DebugObjectD3D12.h"
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/LinkedList.h"
#include "include/gpgmm_d3d12.h"

#include <functional>  // for std::function
#include <memory>

namespace gpgmm::d3d12 {

    class ResidencyManager;

    class Heap final : public MemoryBase, public DebugObject, public LinkNode<Heap>, public IHeap {
      public:
        static HRESULT CreateHeap(const HEAP_DESC& descriptor,
                                  IResidencyManager* const pResidencyManager,
                                  CreateHeapFn&& createHeapFn,
                                  IHeap** ppHeapOut);

        ~Heap() override;

        // IHeap interface
        HEAP_INFO GetInfo() const override;
        bool IsInResidencyLRUCacheForTesting() const override;
        bool IsResidencyLockedForTesting() const override;

        // IMemoryObject
        uint64_t GetSize() const override;
        uint64_t GetAlignment() const override;
        void AddSubAllocationRef() override;
        bool RemoveSubAllocationRef() override;
        IMemoryPool* GetPool() const override;
        void SetPool(IMemoryPool* pool) override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        friend ResidencyManager;

        Heap(ComPtr<ID3D12Pageable> pageable,
             const HEAP_DESC& descriptor,
             bool isResidencyDisabled);

        HRESULT SetDebugNameImpl(LPCWSTR name) override;
        const char* GetTypename() const override;
        DXGI_MEMORY_SEGMENT_GROUP GetMemorySegmentGroup() const;

        // The residency manager must know the last fence value that any portion of the pageable was
        // submitted to be used so that we can ensure this pageable stays resident in memory at
        // least until that fence has completed.
        uint64_t GetLastUsedFenceValue() const;
        void SetLastUsedFenceValue(uint64_t fenceValue);

        void SetResidencyState(RESIDENCY_STATUS newStatus);

        bool IsResidencyLocked() const;

        // Locks residency to ensure the heap cannot be evicted (ex. shader-visible descriptor
        // heaps or mapping resources).
        void AddResidencyLockRef();
        void ReleaseResidencyLock();

        ComPtr<ID3D12Pageable> mPageable;

        // mLastUsedFenceValue denotes the last time this pageable was submitted to the GPU.
        uint64_t mLastUsedFenceValue = 0;
        DXGI_MEMORY_SEGMENT_GROUP mMemorySegmentGroup;
        RefCounted mResidencyLock;
        bool mIsResidencyDisabled;
        RESIDENCY_STATUS mState;
    };
}  // namespace gpgmm::d3d12

#endif
