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

    static const wchar_t* kResourceHeapDebugName = L"GPGMM Resource Heap";

    ResourceHeapAllocator::ResourceHeapAllocator(ResidencyManager* residencyManager,
                                                 ID3D12Device* device,
                                                 D3D12_HEAP_PROPERTIES heapProperties,
                                                 D3D12_HEAP_FLAGS heapFlags)
        : mResidencyManager(residencyManager),
          mDevice(device),
          mHeapProperties(heapProperties),
          mHeapFlags(heapFlags) {
    }

    std::unique_ptr<MemoryAllocation> ResourceHeapAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "ResourceHeapAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        if (request.NeverAllocate) {
            return {};
        }

        HEAP_DESC resourceHeapDesc = {};
        // D3D12 requests (but not requires) the heap size be always a multiple of
        // alignment to avoid wasting bytes.
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_HEAP_INFO
        resourceHeapDesc.SizeInBytes = AlignTo(request.SizeInBytes, request.Alignment);
        resourceHeapDesc.Alignment = request.Alignment;
        resourceHeapDesc.DebugName = kResourceHeapDebugName;

        const bool isResidencyEnabled = (mResidencyManager != nullptr);
        resourceHeapDesc.Flags |= GetHeapFlags(mHeapFlags, isResidencyEnabled);

        if (isResidencyEnabled) {
            resourceHeapDesc.MemorySegmentGroup = GetMemorySegmentGroup(
                mHeapProperties.MemoryPoolPreference, mResidencyManager->IsUMA());
        }

        D3D12_HEAP_DESC heapDesc = {};
        heapDesc.Properties = mHeapProperties;
        heapDesc.SizeInBytes = resourceHeapDesc.SizeInBytes;
        heapDesc.Alignment = resourceHeapDesc.Alignment;
        heapDesc.Flags = mHeapFlags;

        CreateResourceHeapCallbackContext createResourceHeapCallbackContext(mDevice, &heapDesc);
        ComPtr<IHeap> resourceHeap;
        if (FAILED(Heap::CreateHeap(resourceHeapDesc, mResidencyManager,
                                    CreateResourceHeapCallbackContext::CreateHeap,
                                    &createResourceHeapCallbackContext, &resourceHeap))) {
            return {};
        }

        if (resourceHeapDesc.SizeInBytes > request.SizeInBytes) {
            DebugEvent(this, EventMessageId::kAlignmentMismatch)
                << "Resource heap was larger then the requested size (" +
                       std::to_string(resourceHeapDesc.SizeInBytes) + " vs " +
                       std::to_string(request.SizeInBytes) + " bytes).";
        }

        mStats.UsedMemoryUsage += resourceHeapDesc.SizeInBytes;
        mStats.UsedMemoryCount++;

        return std::make_unique<MemoryAllocation>(this, static_cast<Heap*>(resourceHeap.Detach()),
                                                  request.SizeInBytes);
    }

    void ResourceHeapAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        std::lock_guard<std::mutex> lock(mMutex);

        TRACE_EVENT0(TraceEventCategory::kDefault, "ResourceHeapAllocator.DeallocateMemory");

        mStats.UsedMemoryUsage -= allocation->GetSize();
        mStats.UsedMemoryCount--;
        SafeRelease(allocation);
    }

    const char* ResourceHeapAllocator::GetTypename() const {
        return "ResourceHeapAllocator";
    }

    CreateResourceHeapCallbackContext::CreateResourceHeapCallbackContext(ID3D12Device* device,
                                                                         D3D12_HEAP_DESC* heapDesc)
        : mDevice(device), mHeapDesc(heapDesc) {
    }

    HRESULT CreateResourceHeapCallbackContext::CreateHeap(void* pContext,
                                                          ID3D12Pageable** ppPageableOut) {
        CreateResourceHeapCallbackContext* createResourceHeapCallbackContext =
            static_cast<CreateResourceHeapCallbackContext*>(pContext);

        return createResourceHeapCallbackContext->CreateHeap(ppPageableOut);
    }

    HRESULT CreateResourceHeapCallbackContext::CreateHeap(ID3D12Pageable** ppPageableOut) {
        // Non-custom heaps are not allowed to have the pool-specified.
        if (mHeapDesc->Properties.Type != D3D12_HEAP_TYPE_CUSTOM) {
            mHeapDesc->Properties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
        }

        ComPtr<ID3D12Heap> heap;
        ReturnIfFailed(mDevice->CreateHeap(mHeapDesc, IID_PPV_ARGS(&heap)));

        *ppPageableOut = heap.Detach();

        return S_OK;
    }

}  // namespace gpgmm::d3d12
