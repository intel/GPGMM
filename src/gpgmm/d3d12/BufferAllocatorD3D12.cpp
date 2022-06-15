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

#include "gpgmm/d3d12/BufferAllocatorD3D12.h"

#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"

namespace gpgmm::d3d12 {

    BufferAllocator::BufferAllocator(ResourceAllocator* resourceAllocator,
                                     D3D12_HEAP_TYPE heapType,
                                     D3D12_HEAP_FLAGS heapFlags,
                                     D3D12_RESOURCE_FLAGS resourceFlags,
                                     D3D12_RESOURCE_STATES initialResourceState,
                                     uint64_t bufferSize,
                                     uint64_t bufferAlignment)
        : mResourceAllocator(resourceAllocator),
          mHeapType(heapType),
          mHeapFlags(heapFlags),
          mResourceFlags(resourceFlags),
          mInitialResourceState(initialResourceState),
          mBufferSize(bufferSize),
          mBufferAlignment(bufferAlignment) {
    }

    std::unique_ptr<MemoryAllocation> BufferAllocator::TryAllocateMemory(
        const MEMORY_ALLOCATION_REQUEST& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "BufferAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        if (GetMemorySize() != request.SizeInBytes || GetMemoryAlignment() != request.Alignment ||
            request.NeverAllocate) {
            return {};
        }

        D3D12_RESOURCE_ALLOCATION_INFO info = {};
        info.SizeInBytes = request.SizeInBytes;
        info.Alignment = request.Alignment;

        D3D12_RESOURCE_DESC resourceDescriptor;
        resourceDescriptor.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        resourceDescriptor.Alignment = info.Alignment;
        resourceDescriptor.Width = info.SizeInBytes;
        resourceDescriptor.Height = 1;
        resourceDescriptor.DepthOrArraySize = 1;
        resourceDescriptor.MipLevels = 1;
        resourceDescriptor.Format = DXGI_FORMAT_UNKNOWN;
        resourceDescriptor.SampleDesc.Count = 1;
        resourceDescriptor.SampleDesc.Quality = 0;
        resourceDescriptor.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        resourceDescriptor.Flags = mResourceFlags;

        // Optimized clear is not supported for buffers.
        Heap* resourceHeap = nullptr;
        if (FAILED(mResourceAllocator->CreateCommittedResource(
                mHeapType, mHeapFlags, info, &resourceDescriptor,
                /*pOptimizedClearValue*/ nullptr, mInitialResourceState, /*resourceOut*/ nullptr,
                &resourceHeap))) {
            return {};
        }

        mInfo.UsedMemoryUsage += resourceHeap->GetSize();
        mInfo.UsedMemoryCount++;

        return std::make_unique<MemoryAllocation>(this, resourceHeap, request.SizeInBytes);
    }

    void BufferAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "BufferAllocator.DeallocateMemory");
        std::lock_guard<std::mutex> lock(mMutex);

        mInfo.UsedMemoryUsage -= allocation->GetSize();
        mInfo.UsedMemoryCount--;

        SafeRelease(allocation);
    }

    uint64_t BufferAllocator::GetMemorySize() const {
        return mBufferSize;
    }

    uint64_t BufferAllocator::GetMemoryAlignment() const {
        return mBufferAlignment;
    }

}  // namespace gpgmm::d3d12
