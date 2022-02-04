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

#include "gpgmm/d3d12/ResourceAllocationD3D12.h"

#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

#include <utility>

namespace gpgmm { namespace d3d12 {

    namespace {

        // Returns a resource range from the start of the allocation.
        D3D12_RANGE GetResourceRange(const D3D12_RANGE* range, uint64_t offset) {
            if (range == nullptr) {
                return {};
            }
            return {range->Begin + offset, range->End + offset};
        }

    }  // namespace

    ResourceAllocation::ResourceAllocation(ResidencyManager* residencyManager,
                                           MemoryAllocator* subAllocator,
                                           uint64_t offsetFromHeap,
                                           Block* block,
                                           ComPtr<ID3D12Resource> placedResource,
                                           Heap* resourceHeap)
        : MemoryAllocation(subAllocator,
                           resourceHeap,
                           offsetFromHeap,
                           AllocationMethod::kSubAllocated,
                           block),
          mResourceAllocator(nullptr),
          mResidencyManager(residencyManager),
          mResource(std::move(placedResource)),
          mOffsetFromResource(0) {
        TRACE_EVENT_OBJECT_CREATED_WITH_ID("GPUMemoryAllocation", this);
        d3d12::LogObject("GPUMemoryAllocation", this, GetDesc());
    }

    ResourceAllocation::ResourceAllocation(ResidencyManager* residencyManager,
                                           MemoryAllocator* standaloneAllocator,
                                           ComPtr<ID3D12Resource> placedResource,
                                           Heap* resourceHeap)
        : MemoryAllocation(standaloneAllocator,
                           resourceHeap,
                           /*offsetFromHeap*/ 0,
                           AllocationMethod::kStandalone,
                           /*block*/ nullptr),
          mResourceAllocator(nullptr),
          mResidencyManager(residencyManager),
          mResource(std::move(placedResource)),
          mOffsetFromResource(0) {
        TRACE_EVENT_OBJECT_CREATED_WITH_ID("GPUMemoryAllocation", this);
        d3d12::LogObject("GPUMemoryAllocation", this, GetDesc());
    }

    ResourceAllocation::ResourceAllocation(ResidencyManager* residencyManager,
                                           ResourceAllocator* resourceAllocator,
                                           ComPtr<ID3D12Resource> resource,
                                           Heap* resourceHeap)
        : MemoryAllocation(/*memoryAllocator*/ nullptr,
                           resourceHeap,
                           kInvalidOffset,
                           AllocationMethod::kStandalone,
                           /*block*/ nullptr),
          mResourceAllocator(resourceAllocator),
          mResidencyManager(residencyManager),
          mResource(std::move(resource)),
          mOffsetFromResource(0) {
        TRACE_EVENT_OBJECT_CREATED_WITH_ID("GPUMemoryAllocation", this);
        d3d12::LogObject("GPUMemoryAllocation", this, GetDesc());
    }

    ResourceAllocation::ResourceAllocation(ResidencyManager* residencyManager,
                                           MemoryAllocator* subAllocator,
                                           Block* block,
                                           uint64_t offsetFromResource,
                                           ComPtr<ID3D12Resource> resource,
                                           Heap* resourceHeap)
        : MemoryAllocation(subAllocator,
                           resourceHeap,
                           kInvalidOffset,
                           AllocationMethod::kSubAllocatedWithin,
                           block),
          mResourceAllocator(nullptr),
          mResidencyManager(residencyManager),
          mResource(std::move(resource)),
          mOffsetFromResource(offsetFromResource) {
        TRACE_EVENT_OBJECT_CREATED_WITH_ID("GPUMemoryAllocation", this);
        d3d12::LogObject("GPUMemoryAllocation", this, GetDesc());
    }

    ResourceAllocation::~ResourceAllocation() {
        TRACE_EVENT_OBJECT_DELETED_WITH_ID("GPUMemoryAllocation", this);
    }

    void ResourceAllocation::DeleteThis() {
        TRACE_EVENT_CALL_SCOPED("ResourceAllocation.Release");

        if (GetAllocator() != nullptr) {
            GetAllocator()->DeallocateMemory(this);
        } else {
            ASSERT(GetMethod() == AllocationMethod::kStandalone);
            ASSERT(mResourceAllocator != nullptr);
            Heap* resourceHeap = ToBackendType(GetMemory());
            mResourceAllocator->FreeResourceHeap(resourceHeap);
        }

        mResource.Reset();
        MemoryAllocation::Reset();

        IUnknownImpl::DeleteThis();
    }

    ID3D12Resource* ResourceAllocation::GetResource() const {
        return mResource.Get();
    }

    HRESULT ResourceAllocation::Map(uint32_t subresource,
                                    const D3D12_RANGE* readRange,
                                    void** dataOut) {
        Heap* resourceHeap = ToBackendType(GetMemory());
        if (resourceHeap == nullptr) {
            return E_INVALIDARG;
        }

        // Allocation coordinates relative to the resource cannot be used when specifying
        // subresource-relative coordinates.
        if (subresource > 0 && GetMethod() == AllocationMethod::kSubAllocatedWithin) {
            return E_INVALIDARG;
        }

        if (mResidencyManager != nullptr) {
            ReturnIfFailed(mResidencyManager->LockHeap(resourceHeap));
        }

        // Range coordinates are always subresource-relative so the range should only be
        // adjusted if the entire resource is being mapped where allocation coordinates are relative
        // to entire resource.
        D3D12_RANGE newReadRange{};
        const D3D12_RANGE* newReadRangePtr = readRange;
        if (newReadRangePtr != nullptr && mOffsetFromResource > 0) {
            ASSERT(subresource == 0);
            newReadRange = GetResourceRange(readRange, mOffsetFromResource);
            newReadRangePtr = &newReadRange;
        }

        void* mappedData = nullptr;
        ReturnIfFailed(mResource->Map(subresource, newReadRangePtr, &mappedData));

        if (dataOut != nullptr) {
            *dataOut = static_cast<uint8_t*>(mappedData) + mOffsetFromResource;
        }

        return S_OK;
    }

    void ResourceAllocation::Unmap(uint32_t subresource, const D3D12_RANGE* writtenRange) {
        Heap* resourceHeap = ToBackendType(GetMemory());
        if (resourceHeap == nullptr) {
            return;
        }

        // Allocation coordinates relative to the resource cannot be used when specifying
        // subresource-relative coordinates.
        ASSERT(subresource == 0 || GetMethod() != AllocationMethod::kSubAllocatedWithin);

        if (mResidencyManager != nullptr) {
            mResidencyManager->UnlockHeap(resourceHeap);
        }

        D3D12_RANGE newWrittenRange{};
        const D3D12_RANGE* newWrittenRangePtr = writtenRange;
        if (newWrittenRangePtr != nullptr && mOffsetFromResource > 0) {
            ASSERT(subresource == 0);
            newWrittenRange = GetResourceRange(newWrittenRangePtr, mOffsetFromResource);
            newWrittenRangePtr = &newWrittenRange;
        }

        mResource->Unmap(subresource, newWrittenRangePtr);
    }

    HRESULT ResourceAllocation::UpdateResidency(ResidencySet* residencySet) {
        Heap* resourceHeap = ToBackendType(GetMemory());
        if (resourceHeap == nullptr) {
            return E_INVALIDARG;
        }

        if (mResidencyManager == nullptr) {
            return E_FAIL;
        }

        return resourceHeap->UpdateResidency(residencySet);
    }

    D3D12_GPU_VIRTUAL_ADDRESS ResourceAllocation::GetGPUVirtualAddress() const {
        ASSERT(mResource != nullptr);
        return mResource->GetGPUVirtualAddress() + mOffsetFromResource;
    }

    uint64_t ResourceAllocation::GetOffsetFromResource() const {
        return mOffsetFromResource;
    }

    RESOURCE_ALLOCATION_DESC ResourceAllocation::GetDesc() const {
        Heap* resourceHeap = ToBackendType(GetMemory());
        ASSERT(resourceHeap != nullptr);

        return {GetSize(), GetOffset(), mOffsetFromResource, GetMethod(), resourceHeap};
    }
}}  // namespace gpgmm::d3d12
