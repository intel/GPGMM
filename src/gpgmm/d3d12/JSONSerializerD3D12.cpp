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

#include "gpgmm/d3d12/JSONSerializerD3D12.h"

#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/ResidencyHeapD3D12.h"
#include "gpgmm/d3d12/ResidencyListD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/WindowsUtils.h"

namespace gpgmm::d3d12 {

    // static
    JSONDict JSONSerializer::Serialize() {
        return {};
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESOURCE_ALLOCATOR_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        dict.AddItem("MinLogLevel", desc.MinLogLevel);
        dict.AddItem("MinRecordLevel", desc.MinRecordLevel);
        dict.AddItem("RecordOptions", Serialize(desc.RecordOptions));
        dict.AddItem("ResourceHeapTier", desc.ResourceHeapTier);
        dict.AddItem("SubAllocationAlgorithm", desc.SubAllocationAlgorithm);
        dict.AddItem("PoolAlgorithm", desc.PoolAlgorithm);
        dict.AddItem("PreferredResourceHeapSize", desc.PreferredResourceHeapSize);
        dict.AddItem("MaxResourceHeapSize", desc.MaxResourceHeapSize);
        dict.AddItem("ResourceHeapFragmentationLimit", desc.ResourceHeapFragmentationLimit);
        dict.AddItem("ResourceHeapGrowthFactor", desc.ResourceHeapGrowthFactor);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESOURCE_ALLOCATOR_CREATE_RESOURCE_PARAMS& params) {
        JSONDict dict;
        dict.AddItem("allocationDescriptor", Serialize(params.allocationDescriptor));
        dict.AddItem("resourceDescriptor", Serialize(params.resourceDescriptor));
        dict.AddItem("initialResourceState", params.initialResourceState);
        dict.AddItem("clearValue", Serialize(params.clearValue));
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESOURCE_ALLOCATION_DESC& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        dict.AddItem("HeapType", desc.HeapType);
        dict.AddItem("ExtraRequiredHeapFlags", desc.ExtraRequiredHeapFlags);
        dict.AddItem("ExtraRequiredResourcePadding", desc.ExtraRequiredResourcePadding);
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
    JSONDict JSONSerializer::Serialize(const RESIDENCY_HEAP_CREATE_RESIDENCY_HEAP_PARAMS& params) {
        JSONDict dict;

        ComPtr<ID3D12Heap> heap;
        if (SUCCEEDED(params.Pageable->QueryInterface(IID_PPV_ARGS(&heap)))) {
            dict.AddItem("Heap", Serialize(heap->GetDesc()));
            return dict;
        }

        ComPtr<ID3D12Resource> committedResource;
        if (SUCCEEDED(params.Pageable->QueryInterface(IID_PPV_ARGS(&committedResource)))) {
            JSONDict heapDict;
            D3D12_HEAP_PROPERTIES heapProperties = {};
            D3D12_HEAP_FLAGS heapFlags = {};
            if (SUCCEEDED(committedResource->GetHeapProperties(&heapProperties, &heapFlags))) {
                heapDict.AddItem("Properties", Serialize(heapProperties));
                heapDict.AddItem("Flags", heapFlags);
                heapDict.AddItem("SizeInBytes", params.HeapDescriptor.SizeInBytes);
                heapDict.AddItem("Alignment", params.HeapDescriptor.Alignment);
                dict.AddItem("Heap", heapDict);
            }
        }

        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESIDENCY_HEAP_DESC& desc) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", desc.SizeInBytes);
        dict.AddItem("Alignment", desc.Alignment);
        dict.AddItem("HeapSegment", desc.HeapSegment);
        dict.AddItem("Flags", desc.Flags);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESIDENCY_HEAP_INFO& info) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", info.SizeInBytes);
        dict.AddItem("Alignment", info.Alignment);
        dict.AddItem("IsLocked", info.IsLocked);
        dict.AddItem("Status", info.Status);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RESOURCE_RESOURCE_ALLOCATION_DESC& desc) {
        JSONDict dict;
        dict.AddItem("SizeInBytes", desc.SizeInBytes);
        dict.AddItem("HeapOffset", desc.HeapOffset);
        dict.AddItem("OffsetFromResource", desc.OffsetFromResource);
        dict.AddItem("Method", static_cast<uint32_t>(desc.Type));
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
    JSONDict JSONSerializer::Serialize(
        const RESIDENCY_MANAGER_EXECUTE_COMMAND_LISTS_PARAMS& params) {
        JSONDict dict;
        JSONArray residencyLists;
        for (uint64_t i = 0; i < params.Count; i++) {
            JSONDict residencyListDict;
            JSONArray heapArray;
            ResidencyList* residencyList = static_cast<ResidencyList*>(params.ResidencyLists[i]);
            for (IResidencyHeap* heap : *residencyList) {
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
    JSONDict JSONSerializer::Serialize(const RESIDENCY_MANAGER_DESC& desc) {
        JSONDict dict;
        dict.AddItem("MinLogLevel", desc.MinLogLevel);
        dict.AddItem("MinRecordLevel", desc.MinRecordLevel);
        dict.AddItem("Flags", desc.Flags);
        dict.AddItem("RecordOptions", Serialize(desc.RecordOptions));
        dict.AddItem("MaxPctOfMemoryToBudget", desc.MaxPctOfMemoryToBudget);
        dict.AddItem("MinPctOfBudgetToReserve", desc.MinPctOfBudgetToReserve);
        dict.AddItem("MaxBudgetInBytes", desc.MaxBudgetInBytes);
        dict.AddItem("EvictSizeInBytes", desc.EvictSizeInBytes);
        return dict;
    }

    // static
    JSONDict JSONSerializer::Serialize(const RECORD_OPTIONS& desc) {
        JSONDict dict;
        dict.AddItem("Flags", desc.Flags);
        return dict;
    }

}  // namespace gpgmm::d3d12
