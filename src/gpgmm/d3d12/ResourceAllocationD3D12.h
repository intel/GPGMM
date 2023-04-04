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

#ifndef GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
#define GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_

#include "gpgmm/common/MemoryAllocation.h"
#include "gpgmm/d3d12/DebugObjectD3D12.h"

#include <gpgmm_d3d12.h>

namespace gpgmm::d3d12 {

    class DebugResourceAllocator;
    class ResidencyManager;
    class ResourceAllocator;
    class Heap;

    struct RESOURCE_ALLOCATION_DESC {
        uint64_t SizeInBytes;
        uint64_t HeapOffset;
        uint64_t OffsetFromResource;
        ALLOCATION_METHOD Method;
        LPCWSTR DebugName;
    };

    class ResourceAllocation final : public MemoryAllocation,
                                     public DebugObject,
                                     public IResourceAllocation {
      public:
        ~ResourceAllocation() override;

        // IResourceAllocation interface
        HRESULT Map(uint32_t subresource, const D3D12_RANGE* pReadRange, void** ppDataOut) override;
        void Unmap(uint32_t subresource, const D3D12_RANGE* pWrittenRange) override;
        ID3D12Resource* GetResource() const override;
        D3D12_GPU_VIRTUAL_ADDRESS GetGPUVirtualAddress() const override;
        uint64_t GetOffsetFromResource() const override;
        RESOURCE_ALLOCATION_INFO GetInfo() const override;
        IHeap* GetMemory() const override;

        DEFINE_UNKNOWN_OVERRIDES()

        // IDebugObject interface
        LPCWSTR GetDebugName() const override;
        HRESULT SetDebugName(LPCWSTR Name) override;

      private:
        friend ResourceAllocator;

        ResourceAllocation(const RESOURCE_ALLOCATION_DESC& desc,
                           ResidencyManager* residencyManager,
                           MemoryAllocator* allocator,
                           Heap* resourceHeap,
                           MemoryBlock* block,
                           ComPtr<ID3D12Resource> resource);

        // Only DebugResourceAllocator may inject itself to ensure |this| cannot leak.
        friend DebugResourceAllocator;
        void SetDebugAllocator(MemoryAllocator* allocator);

        HRESULT SetDebugNameImpl(LPCWSTR name) override;

        void DeleteThis() override;

        // ObjectBase interface
        const char* GetTypename() const override;
        bool IsExternal() const override;

        ResidencyManager* const mResidencyManager;
        ComPtr<ID3D12Resource> mResource;

        const uint64_t mOffsetFromResource;
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
