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

#include "gpgmm/d3d12/BufferAllocatorD3D12.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/ResidencyHeapD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm::d3d12 {

    BufferAllocator::BufferAllocator(ScopedRef<ResourceAllocator> resourceAllocator,
                                     D3D12_HEAP_PROPERTIES heapProperties,
                                     D3D12_HEAP_FLAGS heapFlags,
                                     D3D12_RESOURCE_FLAGS bufferFlags,
                                     D3D12_RESOURCE_STATES initialBufferState)
        : MemoryAllocatorBase(resourceAllocator.Detach()),
          mHeapProperties(heapProperties),
          mHeapFlags(heapFlags),
          mBufferFlags(bufferFlags),
          mInitialBufferState(initialBufferState) {
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> BufferAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "BufferAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        if (request.NeverAllocate) {
            return {};
        }

        D3D12_RESOURCE_ALLOCATION_INFO info = {};
        info.SizeInBytes = AlignTo(request.SizeInBytes, request.Alignment);
        info.Alignment = request.Alignment;

        D3D12_RESOURCE_DESC bufferDescriptor;
        bufferDescriptor.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        bufferDescriptor.Alignment = info.Alignment;
        bufferDescriptor.Width = info.SizeInBytes;
        bufferDescriptor.Height = 1;
        bufferDescriptor.DepthOrArraySize = 1;
        bufferDescriptor.MipLevels = 1;
        bufferDescriptor.Format = DXGI_FORMAT_UNKNOWN;
        bufferDescriptor.SampleDesc.Count = 1;
        bufferDescriptor.SampleDesc.Quality = 0;
        bufferDescriptor.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        bufferDescriptor.Flags = mBufferFlags;

        // Optimized clear is not supported for buffers.
        ComPtr<ResidencyHeap> resourceHeap;
        HRESULT hr = ToBackend(GetNextInChain())
                         ->CreateCommittedResource(
                             mHeapProperties, mHeapFlags, info, &bufferDescriptor,
                             /*pOptimizedClearValue*/ nullptr, mInitialBufferState, &resourceHeap);

        if (FAILED(hr)) {
            return GetErrorCode(hr);
        }

        if (info.SizeInBytes > request.SizeInBytes) {
            WarnLog(MessageId::kPerformanceWarning, this)
                << "Resource heap was larger then the requested: "
                << GetBytesToSizeInUnits(info.SizeInBytes) << " vs "
                << GetBytesToSizeInUnits(request.SizeInBytes) << ".";
        }

        mStats.UsedMemoryUsage += resourceHeap->GetSize();
        mStats.UsedMemoryCount++;

        return std::make_unique<MemoryAllocationBase>(this, resourceHeap.Detach(),
                                                      request.SizeInBytes);
    }

    void BufferAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "BufferAllocator.DeallocateMemory");
        std::lock_guard<std::mutex> lock(mMutex);

        mStats.UsedMemoryUsage -= allocation->GetSize();
        mStats.UsedMemoryCount--;

        SafeRelease(allocation);
    }
}  // namespace gpgmm::d3d12
