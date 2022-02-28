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

#include "gpgmm/d3d12/SerializerD3D12.h"

#include "gpgmm/TraceEvent.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm { namespace d3d12 {

    // static
    JSONDict Serializer::Serialize(const ALLOCATOR_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        dict.AddItem("RecordOptions", Serialize(desc.RecordOptions));
        dict.AddItem("IsUMA", desc.IsUMA);
        dict.AddItem("ResourceHeapTier", desc.ResourceHeapTier);
        dict.AddItem("PreferredResourceHeapSize", desc.PreferredResourceHeapSize);
        dict.AddItem("MaxResourceHeapSize", desc.MaxResourceHeapSize);
        dict.AddItem("MaxResourceSizeForPooling", desc.MaxResourceSizeForPooling);
        dict.AddItem("MaxVideoMemoryBudget", desc.MaxVideoMemoryBudget);
        dict.AddItem("TotalResourceBudgetLimit", desc.TotalResourceBudgetLimit);
        dict.AddItem("VideoMemoryEvictSize", desc.VideoMemoryEvictSize);
        dict.AddItem("ResourceFragmentationLimit", desc.ResourceFragmentationLimit);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const CREATE_RESOURCE_DESC& desc) {
        JSONDict dict;
        dict.AddItem("allocationDescriptor", Serialize(desc.allocationDescriptor));
        dict.AddItem("resourceDescriptor", Serialize(desc.resourceDescriptor));
        dict.AddItem("initialResourceState", desc.initialResourceState);
        dict.AddItem("clearValue", Serialize(desc.clearValue));
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const ALLOCATION_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        dict.AddItem("HeapType", desc.HeapType);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const D3D12_RESOURCE_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Dimension", desc.Dimension);
        dict.AddItem("Alignment", desc.Alignment);
        dict.AddItem("Width", desc.Width);
        dict.AddItem("Height", desc.Height);
        dict.AddItem("DepthOrArraySize", desc.DepthOrArraySize);
        dict.AddItem("MipLevels", desc.MipLevels);
        dict.AddItem("Format", desc.Format);
        dict.AddItem("Layout", desc.Layout);
        dict.AddItem("SampleDesc", Serialize(desc.SampleDesc));
        dict.AddItem("Flags", desc.Flags);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const ALLOCATOR_RECORD_OPTIONS& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const D3D12_DEPTH_STENCIL_VALUE& depthStencilValue) {
        JSONDict dict;
        dict.AddItem("Depth", depthStencilValue.Depth);
        dict.AddItem("Stencil", depthStencilValue.Stencil);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const FLOAT rgba[4]) {
        JSONDict dict;
        dict.AddItem("R", rgba[0]);
        dict.AddItem("G", rgba[1]);
        dict.AddItem("B", rgba[2]);
        dict.AddItem("A", rgba[3]);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const D3D12_CLEAR_VALUE* clearValue) {
        JSONDict dict;
        if (clearValue == nullptr) {
            return dict;
        }

        dict.AddItem("Format", clearValue->Format);

        if (IsDepthFormat(clearValue->Format)) {
            dict.AddItem("DepthStencil", Serialize(clearValue->DepthStencil));
        } else {
            dict.AddItem("Color", Serialize(clearValue->Color));
        }

        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const DXGI_SAMPLE_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Count", desc.Count);
        dict.AddItem("Quality", desc.Quality);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const HEAP_INFO& desc) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", desc.SizeInBytes);
        dict.AddItem("IsResident", desc.IsResident);
        dict.AddItem("MemorySegmentGroup", desc.MemorySegmentGroup);
        dict.AddItem("SubAllocatedRefs", desc.SubAllocatedRefs);
        if (desc.MemoryPool != nullptr) {
            dict.AddItem("MemoryPool", gpgmm::Serializer::Serialize(desc.MemoryPool));
        }

        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const RESOURCE_ALLOCATION_INFO& desc) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", desc.SizeInBytes);
        dict.AddItem("HeapOffset", desc.HeapOffset);
        dict.AddItem("OffsetFromResource", desc.OffsetFromResource);
        dict.AddItem("Method", desc.Method);
        dict.AddItem("ResourceHeap", gpgmm::Serializer::Serialize(desc.ResourceHeap));
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const ALLOCATOR_MESSAGE& desc) {
        JSONDict dict;
        dict.AddItem("Description", desc.Description);
        dict.AddItem("ID", desc.ID);
        return dict;
    }

}}  // namespace gpgmm::d3d12
