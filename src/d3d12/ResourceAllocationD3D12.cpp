// Copyright 2019 The Dawn Authors
// Copyright 2021 The GPGMM Authors
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

#include "src/d3d12/ResourceAllocationD3D12.h"

#include "src/MemoryAllocator.h"
#include "src/TraceEvent.h"
#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResidencyManagerD3D12.h"
#include "src/d3d12/ResourceAllocatorD3D12.h"
#include "src/d3d12/UtilsD3D12.h"

#include <utility>

namespace gpgmm { namespace d3d12 {
    ResourceAllocation::ResourceAllocation(ResidencyManager* residencyManager,
                                           MemoryAllocator* memoryAllocator,
                                           const AllocationInfo& info,
                                           ComPtr<ID3D12Resource> resource,
                                           Heap* resourceHeap)
        : MemoryAllocation(memoryAllocator, info, kInvalidOffset, resourceHeap),
          mResourceAllocator(nullptr),
          mResidencyManager(residencyManager),
          mResource(std::move(resource)) {
        GPGMM_OBJECT_NEW_INSTANCE("ResourceAllocation");
    }

    ResourceAllocation::ResourceAllocation(ResidencyManager* residencyManager,
                                           ResourceAllocator* resourceAllocator,
                                           const AllocationInfo& info,
                                           ComPtr<ID3D12Resource> resource,
                                           Heap* resourceHeap)
        : MemoryAllocation(/*memoryAllocator*/ nullptr, info, kInvalidOffset, resourceHeap),
          mResourceAllocator(resourceAllocator),
          mResidencyManager(residencyManager),
          mResource(std::move(resource)) {
        GPGMM_OBJECT_NEW_INSTANCE("ResourceAllocation");
    }

    ResourceAllocation::~ResourceAllocation() {
        GPGMM_OBJECT_DELETE_INSTANCE("ResourceAllocation");
    }

    void ResourceAllocation::DeleteThis() {
        GPGMM_API_TRACE_FUNCTION_BEGIN();

        if (GetAllocator() != nullptr) {
            GetAllocator()->DeallocateMemory(this);
        } else {
            ASSERT(mResourceAllocator != nullptr);
            Heap* resourceHeap = static_cast<Heap*>(GetMemory());
            mResourceAllocator->FreeResourceHeap(resourceHeap);
        }

        mResource.Reset();
        MemoryAllocation::Reset();

        IUnknownImpl::DeleteThis();

        GPGMM_API_TRACE_FUNCTION_END();
    }

    ID3D12Resource* ResourceAllocation::GetResource() const {
        return mResource.Get();
    }

    HRESULT ResourceAllocation::Map(uint32_t subresource,
                                    const D3D12_RANGE* readRange,
                                    void** dataOut) {
        Heap* resourceHeap = static_cast<Heap*>(GetMemory());
        if (resourceHeap == nullptr) {
            return E_INVALIDARG;
        }

        if (mResidencyManager != nullptr) {
            ReturnIfFailed(mResidencyManager->LockHeap(resourceHeap));
        }

        return mResource->Map(subresource, readRange, dataOut);
    }

    void ResourceAllocation::Unmap(uint32_t subresource, const D3D12_RANGE* writtenRange) {
        Heap* resourceHeap = static_cast<Heap*>(GetMemory());
        if (resourceHeap == nullptr) {
            return;
        }
        if (mResidencyManager != nullptr) {
            mResidencyManager->UnlockHeap(resourceHeap);
        }

        mResource->Unmap(subresource, writtenRange);
    }

    HRESULT ResourceAllocation::UpdateResidency(ResidencySet* residencySet) {
        Heap* resourceHeap = static_cast<Heap*>(GetMemory());
        if (resourceHeap == nullptr) {
            return E_INVALIDARG;
        }

        if (mResidencyManager == nullptr) {
            return E_FAIL;
        }

        return resourceHeap->UpdateResidency(residencySet);
    }
}}  // namespace gpgmm::d3d12
