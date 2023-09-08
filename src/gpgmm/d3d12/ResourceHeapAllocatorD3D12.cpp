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
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/ResidencyHeapD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm::d3d12 {

    ResourceHeapAllocator::ResourceHeapAllocator(ResidencyManager* residencyManager,
                                                 ID3D12Device* device,
                                                 D3D12_HEAP_PROPERTIES heapProperties,
                                                 D3D12_HEAP_FLAGS heapFlags,
                                                 bool alwaysCreatedInBudget)
        : mResidencyManager(residencyManager),
          mDevice(device),
          mHeapProperties(heapProperties),
          mHeapFlags(heapFlags),
          mIsAlwaysCreatedInBudget(alwaysCreatedInBudget) {
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> ResourceHeapAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResourceHeapAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        if (request.NeverAllocate) {
            return {};
        }

        RESIDENCY_HEAP_DESC resourceHeapDesc = {};
        // D3D12 requests (but not requires) the heap size be always a multiple of
        // alignment to avoid wasting bytes.
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_HEAP_INFO
        resourceHeapDesc.SizeInBytes = AlignTo(request.SizeInBytes, request.Alignment);
        resourceHeapDesc.Alignment = request.Alignment;

        const bool isResidencyEnabled = (mResidencyManager != nullptr);
        if (isResidencyEnabled) {
            resourceHeapDesc.Flags |= GetHeapFlags(mHeapFlags, mIsAlwaysCreatedInBudget);
            resourceHeapDesc.HeapSegment =
                GetHeapSegment(mHeapProperties.MemoryPoolPreference, mResidencyManager->IsUMA());
        }

        D3D12_HEAP_DESC heapDesc = {};
        heapDesc.Properties = mHeapProperties;
        heapDesc.SizeInBytes = resourceHeapDesc.SizeInBytes;
        heapDesc.Alignment = resourceHeapDesc.Alignment;
        heapDesc.Flags = mHeapFlags;

        CreateResourceHeapCallbackContext createResourceHeapCallbackContext(mDevice, &heapDesc);
        ComPtr<IResidencyHeap> resourceHeap;
        HRESULT hr = ResidencyHeap::CreateResidencyHeap(
            resourceHeapDesc, mResidencyManager, CreateResourceHeapCallbackContext::CreateHeap,
            &createResourceHeapCallbackContext, &resourceHeap);
        if (FAILED(hr)) {
            return GetErrorCode(hr);
        }

        resourceHeap->SetDebugName(L"GPGMM Resource Heap");

        mStats.UsedMemoryUsage += resourceHeapDesc.SizeInBytes;
        mStats.UsedMemoryCount++;

        return std::make_unique<MemoryAllocationBase>(
            this, static_cast<ResidencyHeap*>(resourceHeap.Detach()), request.SizeInBytes);
    }

    void ResourceHeapAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) {
        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResourceHeapAllocator.DeallocateMemory");

        mStats.UsedMemoryUsage -= allocation->GetSize();
        mStats.UsedMemoryCount--;
        SafeRelease(allocation);
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
        GPGMM_RETURN_IF_FAILED(mDevice->CreateHeap(mHeapDesc, IID_PPV_ARGS(&heap)), mDevice);

        *ppPageableOut = heap.Detach();

        return S_OK;
    }

}  // namespace gpgmm::d3d12
