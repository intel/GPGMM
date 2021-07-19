// Copyright 2019 The Dawn Authors
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

#include "src/d3d12/HeapAllocatorD3D12.h"
#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResidencyManagerD3D12.h"
#include "src/d3d12/ResourceAllocatorD3D12.h"

namespace gpgmm { namespace d3d12 {

    HeapAllocator::HeapAllocator(ComPtr<ID3D12Device> device,
                                 ResourceAllocator* resourceAllocator,
                                 D3D12_HEAP_TYPE heapType,
                                 D3D12_HEAP_FLAGS heapFlags,
                                 DXGI_MEMORY_SEGMENT_GROUP memorySegment,
                                 uint64_t heapAlignment)
        : mDevice(device),
          mResourceAllocator(resourceAllocator),
          mHeapType(heapType),
          mHeapFlags(heapFlags),
          mMemorySegment(memorySegment),
          mHeapAlignment(heapAlignment) {
    }

    ResourceMemoryAllocation HeapAllocator::Allocate(uint64_t size) {
        D3D12_HEAP_DESC heapDesc;
        heapDesc.SizeInBytes = size;
        heapDesc.Properties.Type = mHeapType;
        heapDesc.Properties.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
        heapDesc.Properties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
        heapDesc.Properties.CreationNodeMask = 0;
        heapDesc.Properties.VisibleNodeMask = 0;
        heapDesc.Alignment = mHeapAlignment;
        heapDesc.Flags = mHeapFlags;

        // CreateHeap will implicitly make the created heap resident. We must ensure enough free
        // memory exists before allocating to avoid an out-of-memory error when overcommitted.
        ResidencyManager* residencyManager = mResourceAllocator->GetResidencyManager();
        ASSERT(residencyManager != nullptr);

        residencyManager->EnsureCanAllocate(size, mMemorySegment);

        ComPtr<ID3D12Heap> d3d12Heap;
        HRESULT hr = mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&d3d12Heap));
        if (FAILED(hr)) {
            return GPGMM_INVALID_ALLOCATION;
        }

        std::unique_ptr<Heap> heap =
            std::make_unique<Heap>(std::move(d3d12Heap), mMemorySegment, size);

        // Calling CreateHeap implicitly calls MakeResident on the new heap. We must track this to
        // avoid calling MakeResident a second time.
        residencyManager->TrackResidentHeap(heap.get());

        AllocationInfo info = {};
        info.mMethod = AllocationMethod::kDirect;
        return {mResourceAllocator, info, /*offset*/ 0,
                static_cast<ResourceMemoryBase*>(heap.release())};
    }

    void HeapAllocator::Deallocate(ResourceMemoryAllocation& allocation) {
        mResourceAllocator->FreeResourceHeap(allocation);
    }

    void HeapAllocator::Release() {
        ASSERT(false);
    }

}}  // namespace gpgmm::d3d12
