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

#include "gpgmm/d3d12/ResourceAllocationD3D12.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/LogD3D12.h"
#include "gpgmm/d3d12/ResidencyHeapD3D12.h"
#include "gpgmm/d3d12/ResidencyListD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

#include <utility>

namespace gpgmm::d3d12 {

    namespace {

        // Returns a resource range from the start of the allocation.
        D3D12_RANGE GetResourceRange(const D3D12_RANGE* range, size_t offset) {
            if (range == nullptr) {
                return {};
            }
            return {range->Begin + offset, range->End + offset};
        }

    }  // namespace

    ResourceAllocation::ResourceAllocation(const RESOURCE_RESOURCE_ALLOCATION_DESC& desc,
                                           ResourceAllocator* resourceAllocator,
                                           MemoryAllocatorBase* allocator,
                                           ResidencyHeap* resourceHeap,
                                           MemoryBlock* block,
                                           ComPtr<ID3D12Resource> resource)
        : MemoryAllocationBase(allocator,
                               resourceHeap,
                               desc.HeapOffset,
                               static_cast<AllocationMethod>(desc.Type),
                               block,
                               desc.SizeInBytes),
          mResourceAllocator(std::move(resourceAllocator)),
          mResource(std::move(resource)),
          mOffsetFromResource(desc.OffsetFromResource) {
        ASSERT(resourceHeap != nullptr);
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);
    }

    ResourceAllocation::~ResourceAllocation() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
    }

    void ResourceAllocation::DeleteThis() {
        if (mMappedCount.GetRefCount() > 0) {
            WarnLog(MessageId::kPerformanceWarning, this)
                << "Destroying a mapped resource allocation is allowed but discouraged. Please "
                   "call Unmap the same number of times as Map before releasing the resource "
                   "allocation.";
        }

        // If the developer forgots to unlock the heap, do so now so the heap can be made eligable
        // for eviction.
        ResidencyHeap* residencyHeap = static_cast<ResidencyHeap*>(GetMemory());
        if (SUCCEEDED(residencyHeap->GetResidencyManager(nullptr)) &&
            GPGMM_UNSUCCESSFUL(residencyHeap->Unlock())) {
            WarnLog(MessageId::kPerformanceWarning, this)
                << "Destroying a locked resource allocation is allowed but discouraged. Please "
                   "call UnlockHeap the same number of times as LockHeap before releasing the "
                   "resource allocation.";
        }

        GetAllocator()->DeallocateMemory(std::unique_ptr<MemoryAllocationBase>(this));
    }

    ID3D12Resource* ResourceAllocation::GetResource() const {
        return mResource.Get();
    }

    HRESULT ResourceAllocation::Map(uint32_t subresource,
                                    const D3D12_RANGE* pReadRange,
                                    void** ppDataOut) {
        // Allocation coordinates relative to the resource cannot be used when specifying
        // subresource-relative coordinates.
        if (subresource > 0 && GetInfo().Type == RESOURCE_ALLOCATION_TYPE_SUBALLOCATED_WITHIN) {
            ErrorLog(ErrorCode::kBadOperation, this)
                << "Mapping a resource allocation within cannot use subresource-relative "
                   "coordinates.";
            return GetErrorResult(ErrorCode::kBadOperation);
        }

        ResidencyHeap* residencyHeap = static_cast<ResidencyHeap*>(GetMemory());
        if (SUCCEEDED(residencyHeap->GetResidencyManager(nullptr))) {
            GPGMM_RETURN_IF_FAILED(residencyHeap->Lock(), GetDevice(mResource.Get()).Get());
        }

        // Range coordinates are always subresource-relative so the range should only be
        // adjusted if the entire resource is being mapped where allocation coordinates are relative
        // to entire resource.
        D3D12_RANGE newReadRange{};
        const D3D12_RANGE* newReadRangePtr = pReadRange;
        if (newReadRangePtr != nullptr && mOffsetFromResource > 0) {
            ASSERT(subresource == 0);
            newReadRange = GetResourceRange(pReadRange, static_cast<size_t>(mOffsetFromResource));
            newReadRangePtr = &newReadRange;
        }

        void* mappedData = nullptr;
        GPGMM_RETURN_IF_FAILED(mResource->Map(subresource, newReadRangePtr, &mappedData),
                               GetDevice(mResource.Get()).Get());

        mMappedCount.Ref();

        if (ppDataOut != nullptr) {
            *ppDataOut = static_cast<uint8_t*>(mappedData) + mOffsetFromResource;
        }

        return S_OK;
    }

    void ResourceAllocation::Unmap(uint32_t subresource, const D3D12_RANGE* pWrittenRange) {
        // Allocation coordinates relative to the resource cannot be used when specifying
        // subresource-relative coordinates.
        if (subresource > 0 && GetInfo().Type == RESOURCE_ALLOCATION_TYPE_SUBALLOCATED_WITHIN) {
            ErrorLog(ErrorCode::kBadOperation, this)
                << "Unmapping a resource allocation within cannot use subresource-relative "
                   "coordinates.";
            return;
        }

        // Underlying heap cannot be evicted until the last Unmap.
        ResidencyHeap* residencyHeap = static_cast<ResidencyHeap*>(GetMemory());
        if (mMappedCount.Unref() && SUCCEEDED(residencyHeap->GetResidencyManager(nullptr))) {
            residencyHeap->Unlock();
        }

        D3D12_RANGE newWrittenRange{};
        const D3D12_RANGE* newWrittenRangePtr = pWrittenRange;
        if (newWrittenRangePtr != nullptr && mOffsetFromResource > 0) {
            ASSERT(subresource == 0);
            newWrittenRange =
                GetResourceRange(newWrittenRangePtr, static_cast<size_t>(mOffsetFromResource));
            newWrittenRangePtr = &newWrittenRange;
        }

        mResource->Unmap(subresource, newWrittenRangePtr);
    }

    D3D12_GPU_VIRTUAL_ADDRESS ResourceAllocation::GetGPUVirtualAddress() const {
        ASSERT(mResource != nullptr);
        return mResource->GetGPUVirtualAddress() + mOffsetFromResource;
    }

    uint64_t ResourceAllocation::GetOffsetFromResource() const {
        return mOffsetFromResource;
    }

    RESOURCE_ALLOCATION_INFO ResourceAllocation::GetInfo() const {
        return {GetSize(), GetAlignment(), static_cast<RESOURCE_ALLOCATION_TYPE>(GetMethod())};
    }

    IResidencyHeap* ResourceAllocation::GetMemory() const {
        return static_cast<ResidencyHeap*>(MemoryAllocationBase::GetMemory());
    }

    HRESULT ResourceAllocation::SetDebugNameImpl(LPCWSTR name) {
        // D3D name is set per resource.
        if (GetDebugName() != nullptr &&
            GetInfo().Type == RESOURCE_ALLOCATION_TYPE_SUBALLOCATED_WITHIN) {
            return S_FALSE;
        }

        return SetDebugObjectName(mResource.Get(), name);
    }

    LPCWSTR ResourceAllocation::GetDebugName() const {
        return DebugObject::GetDebugName();
    }

    HRESULT ResourceAllocation::SetDebugName(LPCWSTR Name) {
        return DebugObject::SetDebugName(Name);
    }

    HRESULT ResourceAllocation::GetResourceAllocator(
        IResourceAllocator** ppResourceAllocatorOut) const {
        ComPtr<IResourceAllocator> resourceAllocator(mResourceAllocator);
        if (ppResourceAllocatorOut != nullptr) {
            *ppResourceAllocatorOut = resourceAllocator.Detach();
        } else {
            return S_FALSE;
        }

        return S_OK;
    }

}  // namespace gpgmm::d3d12
