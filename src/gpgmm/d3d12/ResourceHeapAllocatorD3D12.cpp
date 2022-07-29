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

namespace gpgmm::d3d12 {

    ResourceHeapAllocator::ResourceHeapAllocator(ResidencyManager* residencyManager,
                                                 ID3D12Device* device,
                                                 D3D12_HEAP_TYPE heapType,
                                                 D3D12_HEAP_FLAGS heapFlags,
                                                 bool alwaysInBudget)
        : mResidencyManager(residencyManager),
          mDevice(device),
          mHeapType(heapType),
          mHeapFlags(heapFlags),
          mAlwaysInBudget(alwaysInBudget) {
    }

    std::unique_ptr<MemoryAllocation> ResourceHeapAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
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
            DebugEvent(GetTypename(), EventMessageId::AlignmentMismatch)
                << "Resource heap size is larger then the requested size (" +
                       std::to_string(heapSize) + " vs " + std::to_string(request.SizeInBytes) +
                       " bytes).";
        }

        HEAP_DESC resourceHeapDesc = {};
        resourceHeapDesc.SizeInBytes = heapSize;
        resourceHeapDesc.DebugName = "Resource heap";
        resourceHeapDesc.Alignment = request.Alignment;
        resourceHeapDesc.AlwaysInBudget = mAlwaysInBudget;
        resourceHeapDesc.HeapType = mHeapType;

        Heap* resourceHeap = nullptr;
        if (FAILED(Heap::CreateHeap(
                resourceHeapDesc, mResidencyManager,
                [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
                    D3D12_HEAP_PROPERTIES heapProperties = {};
                    heapProperties.Type = resourceHeapDesc.HeapType;

                    D3D12_HEAP_DESC heapDesc = {};
                    heapDesc.Properties = heapProperties;
                    heapDesc.SizeInBytes = resourceHeapDesc.SizeInBytes;
                    heapDesc.Alignment = resourceHeapDesc.Alignment;
                    heapDesc.Flags = mHeapFlags;

                    ComPtr<ID3D12Heap> heap;
                    ReturnIfFailed(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap)));

                    *ppPageableOut = heap.Detach();

                    return S_OK;
                },
                &resourceHeap))) {
            return {};
        }

        mInfo.UsedMemoryUsage += heapSize;
        mInfo.UsedMemoryCount++;

        return std::make_unique<MemoryAllocation>(this, resourceHeap, request.SizeInBytes);
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

}  // namespace gpgmm::d3d12
