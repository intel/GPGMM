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

#ifndef SRC_GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
#define SRC_GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_

#include "gpgmm/common/MemoryAllocation.h"
#include "gpgmm/d3d12/DebugObjectD3D12.h"

#include <gpgmm_d3d12.h>

namespace gpgmm::d3d12 {

    class ResourceAllocator;
    class ResidencyHeap;

    struct RESOURCE_RESOURCE_ALLOCATION_DESC {
        uint64_t SizeInBytes;
        uint64_t HeapOffset;
        uint64_t OffsetFromResource;
        RESOURCE_ALLOCATION_TYPE Type;
    };

    class ResourceAllocation final : public MemoryAllocationBase,
                                     public DebugObject,
                                     public IResourceAllocation {
      public:
        static HRESULT CreateResourceAllocation(const RESOURCE_RESOURCE_ALLOCATION_DESC& descriptor,
                                                ResourceAllocator* pResourceAllocator,
                                                MemoryAllocatorBase* pHeapAllocator,
                                                ResidencyHeap* pResourceHeap,
                                                MemoryBlock* pMemoryBlock,
                                                ComPtr<ID3D12Resource> resource,
                                                ResourceAllocation** ppResourceAllocationOut);

        ~ResourceAllocation() override;

        // IResourceAllocation interface
        HRESULT Map(uint32_t subresource, const D3D12_RANGE* pReadRange, void** ppDataOut) override;
        void Unmap(uint32_t subresource, const D3D12_RANGE* pWrittenRange) override;
        ID3D12Resource* GetResource() const override;
        D3D12_GPU_VIRTUAL_ADDRESS GetGPUVirtualAddress() const override;
        uint64_t GetOffsetFromResource() const override;
        RESOURCE_ALLOCATION_INFO GetInfo() const override;
        IResidencyHeap* GetMemory() const override;
        HRESULT GetResourceAllocator(IResourceAllocator** ppResourceAllocatorOut) const override;

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

      private:
        friend ResourceAllocator;

        ResourceAllocation(const RESOURCE_RESOURCE_ALLOCATION_DESC& desc,
                           ResourceAllocator* resourceAllocator,
                           MemoryAllocatorBase* allocator,
                           ResidencyHeap* resourceHeap,
                           MemoryBlock* block,
                           ComPtr<ID3D12Resource> resource);

        HRESULT SetDebugNameImpl(LPCWSTR name) override;

        void DeleteThis() override;

        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(IResourceAllocation)

        ComPtr<ResourceAllocator> mResourceAllocator;
        ComPtr<ID3D12Resource> mResource;

        const uint64_t mOffsetFromResource;

        // Keeps track of the number of outstanding calls to Map to avoid paging-out those heaps.
        RefCounted mMappedCount = RefCounted{0u};
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
