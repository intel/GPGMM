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

#ifndef GPGMM_D3D12_RESOURCEHEAPALLOCATORD3D12_H_
#define GPGMM_D3D12_RESOURCEHEAPALLOCATORD3D12_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/d3d12/d3d12_platform.h"

namespace gpgmm::d3d12 {

    class ResidencyManager;

    class CreateResourceHeapCallbackContext {
      public:
        CreateResourceHeapCallbackContext(ID3D12Device* device, D3D12_HEAP_DESC* heapDesc);
        static HRESULT CreateHeap(void* pContext, ID3D12Pageable** ppPageableOut);

      private:
        HRESULT CreateHeap(ID3D12Pageable** ppPageableOut);

        ID3D12Device* mDevice;
        D3D12_HEAP_DESC* mHeapDesc;
    };

    // Wrapper to allocate a D3D12 heap for resources of any type.
    class ResourceHeapAllocator final : public MemoryAllocator {
      public:
        ResourceHeapAllocator(ResidencyManager* residencyManager,
                              ID3D12Device* device,
                              D3D12_HEAP_PROPERTIES heapProperties,
                              D3D12_HEAP_FLAGS heapFlags);
        ~ResourceHeapAllocator() override = default;

        // MemoryAllocator interface
        ResultOrError<std::unique_ptr<MemoryAllocation>> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

      private:
        // ObjectBase interface
        const char* GetTypename() const override;

        ResidencyManager* const mResidencyManager;
        ID3D12Device* const mDevice;
        const D3D12_HEAP_PROPERTIES mHeapProperties;
        const D3D12_HEAP_FLAGS mHeapFlags;
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEHEAPALLOCATORD3D12_H_
