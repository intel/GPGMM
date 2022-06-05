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

#include "gpgmm/d3d12/ResourceHeapAllocatorD3D12.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm { namespace d3d12 {

    ResourceHeapAllocator::ResourceHeapAllocator(ResidencyManager* residencyManager,
                                                 ID3D12Device* device,
                                                 D3D12_HEAP_TYPE heapType,
                                                 D3D12_HEAP_FLAGS heapFlags,
                                                 bool isUMA)
        : mResidencyManager(residencyManager),
          mDevice(device),
          mHeapType(heapType),
          mHeapFlags(heapFlags),
          mIsUMA(isUMA) {
    }

    std::unique_ptr<MemoryAllocation> ResourceHeapAllocator::TryAllocateMemory(
        const MEMORY_ALLOCATION_REQUEST& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResourceHeapAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        if (request.NeverAllocate) {
            return {};
        }

        // D3D12 requests (but not requires) the heap size be always a multiple of
        // alignment to avoid wasting bytes.
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_HEAP_INFO
        const uint64_t heapSize = AlignTo(request.SizeInBytes, request.Alignment);
        if (heapSize > request.SizeInBytes) {
            DebugEvent(GetTypename(), MESSAGE_ID_ALIGNMENT_MISMATCH)
                << "Resource heap size is larger then the requested size (" +
                       std::to_string(heapSize) + " vs " + std::to_string(request.SizeInBytes) +
                       " bytes).";
        }

        const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup =
            GetPreferredMemorySegmentGroup(mDevice, mIsUMA, mHeapType);

        // CreateHeap will implicitly make the created heap resident unless
        // D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT is set. Otherwise, CreateHeap could return
        // out-of-memory when overcommitted if Evict() is not called first.
        if (!(mHeapFlags & D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT) && mResidencyManager != nullptr) {
            mResidencyManager->Evict(heapSize, memorySegmentGroup);
        }

        D3D12_HEAP_PROPERTIES heapProperties = {};
        heapProperties.Type = mHeapType;

        D3D12_HEAP_DESC heapDesc = {};
        heapDesc.Properties = heapProperties;
        heapDesc.SizeInBytes = heapSize;
        heapDesc.Alignment = request.Alignment;
        heapDesc.Flags = mHeapFlags;

        ComPtr<ID3D12Heap> heap;
        HRESULT hr = mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap));
        if (FAILED(hr)) {
            InfoEvent(GetTypename()) << " failed to create heap: " << GetErrorMessage(hr);
            return {};
        }

        HEAP_DESC resourceHeapDesc = {};
        resourceHeapDesc.Pageable = std::move(heap);
        resourceHeapDesc.MemorySegmentGroup = memorySegmentGroup;
        resourceHeapDesc.SizeInBytes = heapSize;
        resourceHeapDesc.IsExternal = false;
        resourceHeapDesc.DebugName = "Resource heap";
        resourceHeapDesc.Alignment = heapDesc.Alignment;

        Heap* resourceHeap = nullptr;
        if (FAILED(Heap::CreateHeap(resourceHeapDesc, mResidencyManager, &resourceHeap))) {
            return {};
        }

        mInfo.UsedMemoryUsage += heapSize;
        mInfo.UsedMemoryCount++;

        return std::make_unique<MemoryAllocation>(this, resourceHeap);
    }

    void ResourceHeapAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        std::lock_guard<std::mutex> lock(mMutex);

        TRACE_EVENT0(TraceEventCategory::Default, "ResourceHeapAllocator.DeallocateMemory");

        mInfo.UsedMemoryUsage -= allocation->GetSize();
        mInfo.UsedMemoryCount--;
        SafeRelease(allocation);
    }

    const char* ResourceHeapAllocator::GetTypename() const {
        return "ResourceHeapAllocator";
    }

}}  // namespace gpgmm::d3d12
