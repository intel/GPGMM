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

#include "src/d3d12/ResourceAllocationD3D12.h"

#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResidencyManagerD3D12.h"
#include "src/d3d12/ResourceAllocatorD3D12.h"

#include <utility>

namespace gpgmm { namespace d3d12 {
    ResourceAllocation::ResourceAllocation(ResourceAllocator* allocator,
                                           const AllocationInfo& info,
                                           uint64_t offset,
                                           ComPtr<ID3D12Resource> resource,
                                           Heap* heap)
        : ResourceMemoryAllocation(allocator, info, offset, heap), mResource(std::move(resource)) {
    }

    void ResourceAllocation::ReleaseThis() {
        if (this == nullptr) {
            return;
        }

        ResourceAllocator* allocator = static_cast<ResourceAllocator*>(GetAllocator());
        ASSERT(allocator != nullptr);

        switch (GetInfo().mMethod) {
            case AllocationMethod::kSubAllocated: {
                allocator->FreePlacedResource(*this);
                break;
            }
            case AllocationMethod::kDirect: {
                Heap* resourceHeap = static_cast<Heap*>(GetResourceMemory());
                allocator->FreeResourceHeap(resourceHeap);
                break;
            }
            default: {
                break;
            }
        }

        mResource.Reset();
        ResourceMemoryAllocation::Invalidate();
    }

    ID3D12Resource* ResourceAllocation::GetResource() const {
        return mResource.Get();
    }

    HRESULT ResourceAllocation::SetDebugName(const char* name) {
        return mResource->SetPrivateData(WKPDID_D3DDebugObjectName, std::strlen(name), name);
    }

    HRESULT ResourceAllocation::Map(uint32_t subresource,
                                    const D3D12_RANGE* pRange,
                                    void** ppMappedData) {
        Heap* heap = static_cast<Heap*>(GetResourceMemory());
        if (heap == nullptr) {
            return E_INVALIDARG;
        }

        ResourceAllocator* allocator = static_cast<ResourceAllocator*>(GetAllocator());
        HRESULT hr = allocator->GetResidencyManager()->LockHeap(heap);
        if (FAILED(hr)) {
            return hr;
        }

        return mResource->Map(subresource, pRange, ppMappedData);
    }

    void ResourceAllocation::Unmap(uint32_t subresource, const D3D12_RANGE* pRange) {
        Heap* heap = static_cast<Heap*>(GetResourceMemory());
        if (heap == nullptr) {
            return;
        }
        ResourceAllocator* allocator = static_cast<ResourceAllocator*>(GetAllocator());
        allocator->GetResidencyManager()->UnlockHeap(heap);

        mResource->Unmap(subresource, pRange);
    }

    void ResourceAllocation::UpdateResidency(ResidencySet* residencySet) {
        Heap* heap = static_cast<Heap*>(GetResourceMemory());
        ASSERT(heap != nullptr);
        heap->UpdateResidency(residencySet);
    }

    bool ResourceAllocation::IsResidentForTesting() const {
        Heap* heap = static_cast<Heap*>(GetResourceMemory());
        ASSERT(heap != nullptr);
        return heap->IsResident();
    }

    HRESULT ResourceAllocation::QueryInterface(REFIID riid, void** ppvObject) {
        // Always set out parameter to nullptr, validating it first.
        if (ppvObject == nullptr) {
            return E_INVALIDARG;
        }

        *ppvObject = nullptr;

        if (riid == IID_IUnknown) {
            // Increment reference and return pointer.
            *ppvObject = this;
            ++mRefCount;
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG ResourceAllocation::AddRef() {
        return ++mRefCount;
    }

    ULONG ResourceAllocation::Release() {
        const uint32_t refcount = --mRefCount;
        if (mRefCount == 0) {
            ReleaseThis();
        }
        return refcount;
    }
}}  // namespace gpgmm::d3d12
