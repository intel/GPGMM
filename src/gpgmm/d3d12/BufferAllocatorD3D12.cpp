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
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm::d3d12 {

    BufferAllocator::BufferAllocator(ResourceAllocator* resourceAllocator,
                                     D3D12_HEAP_PROPERTIES heapProperties,
                                     D3D12_HEAP_FLAGS heapFlags,
                                     D3D12_RESOURCE_FLAGS resourceFlags,
                                     D3D12_RESOURCE_STATES initialResourceState)
        : mResourceAllocator(resourceAllocator),
          mHeapProperties(heapProperties),
          mHeapFlags(heapFlags),
          mResourceFlags(resourceFlags),
          mInitialResourceState(initialResourceState) {
    }

    std::unique_ptr<MemoryAllocation> BufferAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "BufferAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        if (request.NeverAllocate) {
            return {};
        }

        const uint64_t heapSize = AlignTo(request.SizeInBytes, request.Alignment);
        if (heapSize > request.SizeInBytes) {
            DebugEvent(GetTypename(), EventMessageId::kAlignmentMismatch)
                << "Resource heap size is larger then the requested size (" +
                       std::to_string(heapSize) + " vs " + std::to_string(request.SizeInBytes) +
                       " bytes).";
        }

        D3D12_RESOURCE_ALLOCATION_INFO info = {};
        info.SizeInBytes = heapSize;
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
        IHeap* resourceHeap = nullptr;
        if (FAILED(mResourceAllocator->CreateCommittedResource(
                mHeapProperties, mHeapFlags, info, &resourceDescriptor,
                /*pOptimizedClearValue*/ nullptr, mInitialResourceState, /*resourceOut*/ nullptr,
                &resourceHeap))) {
            return {};
        }

        mInfo.UsedMemoryUsage += resourceHeap->GetSize();
        mInfo.UsedMemoryCount++;

        return std::make_unique<MemoryAllocation>(this, resourceHeap, request.SizeInBytes);
    }

    void BufferAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "BufferAllocator.DeallocateMemory");
        std::lock_guard<std::mutex> lock(mMutex);

        mInfo.UsedMemoryUsage -= allocation->GetSize();
        mInfo.UsedMemoryCount--;

        SafeRelease(allocation);
    }
}  // namespace gpgmm::d3d12
