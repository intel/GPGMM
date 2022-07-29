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

#include "gpgmm/d3d12/JSONSerializerD3D12.h"

#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/ResidencyListD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm::d3d12 {

    // static
    JSONDict JSONSerializer::Serialize() {
        return {};
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESOURCE_ALLOCATOR_INFO& info) {
        return gpgmm::JSONSerializer::Serialize(info);
    }

    // static
    JSONDict JSONSerializer::Serialize(const ALLOCATOR_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        dict.AddItem("RecordOptions", Serialize(desc.RecordOptions));
        dict.AddItem("ResourceHeapTier", desc.ResourceHeapTier);
        dict.AddItem("PreferredResourceHeapSize", desc.PreferredResourceHeapSize);
        dict.AddItem("MaxResourceHeapSize", desc.MaxResourceHeapSize);
        dict.AddItem("MemoryFragmentationLimit", desc.MemoryFragmentationLimit);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const CREATE_RESOURCE_DESC& desc) {
        JSONDict dict;
        dict.AddItem("allocationDescriptor", Serialize(desc.allocationDescriptor));
        dict.AddItem("resourceDescriptor", Serialize(desc.resourceDescriptor));
        dict.AddItem("initialResourceState", desc.initialResourceState);
        dict.AddItem("clearValue", Serialize(desc.clearValue));
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const ALLOCATION_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        dict.AddItem("HeapType", desc.HeapType);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const D3D12_RESOURCE_DESC& desc) {
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
    JSONDict JSONSerializer::Serialize(const EVENT_RECORD_OPTIONS& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        dict.AddItem("MinMessageLevel", desc.MinMessageLevel);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const D3D12_DEPTH_STENCIL_VALUE& depthStencilValue) {
        JSONDict dict;
        dict.AddItem("Depth", depthStencilValue.Depth);
        dict.AddItem("Stencil", depthStencilValue.Stencil);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const FLOAT rgba[4]) {
        JSONDict dict;
        dict.AddItem("R", rgba[0]);
        dict.AddItem("G", rgba[1]);
        dict.AddItem("B", rgba[2]);
        dict.AddItem("A", rgba[3]);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const D3D12_CLEAR_VALUE* clearValue) {
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
    JSONDict JSONSerializer::Serialize(const DXGI_SAMPLE_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Count", desc.Count);
        dict.AddItem("Quality", desc.Quality);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const CREATE_HEAP_DESC& desc) {
        JSONDict dict;

        ComPtr<ID3D12Heap> heap;
        if (SUCCEEDED(desc.Pageable->QueryInterface(IID_PPV_ARGS(&heap)))) {
            dict.AddItem("Heap", Serialize(heap->GetDesc()));
            return dict;
        }

        ComPtr<ID3D12Resource> committedResource;
        if (SUCCEEDED(desc.Pageable->QueryInterface(IID_PPV_ARGS(&committedResource)))) {
            JSONDict heapDict;
            D3D12_HEAP_PROPERTIES heapProperties = {};
            D3D12_HEAP_FLAGS heapFlags = {};
            if (SUCCEEDED(committedResource->GetHeapProperties(&heapProperties, &heapFlags))) {
                heapDict.AddItem("Properties", Serialize(heapProperties));
                heapDict.AddItem("Flags", heapFlags);
                heapDict.AddItem("SizeInBytes", desc.HeapDescriptor.SizeInBytes);
                heapDict.AddItem("Alignment", desc.HeapDescriptor.Alignment);
                dict.AddItem("Heap", heapDict);
            }
        }

        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const HEAP_DESC& desc) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", desc.SizeInBytes);
        dict.AddItem("Alignment", desc.Alignment);
        dict.AddItem("HeapType", desc.HeapType);
        dict.AddItem("AlwaysInBudget", desc.AlwaysInBudget);
        dict.AddItem("IsExternal", desc.IsExternal);
        dict.AddItem("MemorySegment", desc.MemorySegment);
        dict.AddItem("DebugName", desc.DebugName);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const HEAP_INFO& info) {
        JSONDict dict;
        dict.AddItem("IsResident", info.IsResident);
        dict.AddItem("SubAllocatedRefs", info.SubAllocatedRefs);

        if (info.MemoryPool != nullptr) {
            dict.AddItem("MemoryPool", gpgmm::JSONSerializer::Serialize(info.MemoryPool));
        }

        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESOURCE_ALLOCATION_DESC& desc) {
        JSONDict dict;
        dict.AddItem("RequestSizeInBytes", desc.RequestSizeInBytes);
        dict.AddItem("HeapOffset", desc.HeapOffset);
        dict.AddItem("OffsetFromResource", desc.OffsetFromResource);
        dict.AddItem("Method", desc.Method);
        if (!desc.DebugName.empty()) {
            dict.AddItem("DebugName", desc.DebugName);
        }
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESOURCE_ALLOCATION_INFO& info) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", info.SizeInBytes);
        dict.AddItem("Alignment", info.Alignment);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const D3D12_HEAP_DESC& desc) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", desc.SizeInBytes);
        dict.AddItem("Properties", Serialize(desc.Properties));
        dict.AddItem("Alignment", desc.Alignment);
        dict.AddItem("Flags", desc.Flags);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const D3D12_HEAP_PROPERTIES& desc) {
        JSONDict dict;
        dict.AddItem("Type", desc.Type);
        dict.AddItem("CPUPageProperty", desc.CPUPageProperty);
        dict.AddItem("MemoryPoolPreference", desc.MemoryPoolPreference);
        dict.AddItem("CreationNodeMask", desc.CreationNodeMask);
        dict.AddItem("VisibleNodeMask", desc.VisibleNodeMask);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const EXECUTE_COMMAND_LISTS_DESC& desc) {
        JSONDict dict;
        JSONArray residencyLists;
        for (uint64_t i = 0; i < desc.Count; i++) {
            JSONDict residencyListDict;
            JSONArray heapArray;
            for (const auto& heap : *desc.ResidencyLists[i]) {
                heapArray.AddItem(gpgmm::JSONSerializer::Serialize(heap));
            }
            if (!heapArray.IsEmpty()) {
                residencyListDict.AddItem("Heaps", heapArray);
            }

            residencyLists.AddItem(residencyListDict);
        }

        if (!residencyLists.IsEmpty()) {
            dict.AddItem("ResidencyLists", residencyLists);
        }

        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESIDENCY_DESC& desc) {
        JSONDict dict;
        dict.AddItem("IsUMA", desc.IsUMA);
        dict.AddItem("VideoMemoryBudget", desc.VideoMemoryBudget);
        dict.AddItem("Budget", desc.Budget);
        dict.AddItem("EvictBatchSize", desc.EvictBatchSize);
        dict.AddItem("InitialFenceValue", desc.InitialFenceValue);
        return dict;
    }

}  // namespace gpgmm::d3d12
