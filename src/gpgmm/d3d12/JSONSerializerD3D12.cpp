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

#include "gpgmm/TraceEvent.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

#include <sstream>

namespace gpgmm { namespace d3d12 {

    // static
    std::string JSONSerializer::AppendTo(const ALLOCATOR_DESC& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"Flags\": " << desc.Flags << ", "
           << "\"RecordOptions\": " << AppendTo(desc.RecordOptions) << ", "
           << "\"IsUMA\": " << desc.IsUMA << ", "
           << "\"ResourceHeapTier\": " << desc.ResourceHeapTier << ", "
           << "\"PreferredResourceHeapSize\": " << desc.PreferredResourceHeapSize << ", "
           << "\"MaxResourceHeapSize\": " << desc.MaxResourceHeapSize << ", "
           << "\"MaxResourceSizeForPooling\": " << desc.MaxResourceSizeForPooling << ", "
           << "\"MaxVideoMemoryBudget\": " << desc.MaxVideoMemoryBudget << ", "
           << "\"TotalResourceBudgetLimit\": " << desc.TotalResourceBudgetLimit << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const CREATE_RESOURCE_DESC& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"allocationDescriptor\": " << AppendTo(desc.allocationDescriptor) << ", "
           << "\"resourceDescriptor\": " << AppendTo(desc.resourceDescriptor) << ", "
           << "\"initialResourceState\": " << desc.initialResourceState << ", "
           << "\"clearValue\": " << AppendTo(desc.clearValue) << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const ALLOCATION_DESC& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"Flags\": " << desc.Flags << ", "
           << "\"HeapType\": " << desc.HeapType << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const D3D12_RESOURCE_DESC& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"Dimension\": " << desc.Dimension << ", "
           << "\"Alignment\": " << desc.Alignment << ", "
           << "\"Width\": " << desc.Width << ", "
           << "\"Height\": " << desc.Height << ", "
           << "\"DepthOrArraySize\": " << desc.DepthOrArraySize << ", "
           << "\"MipLevels\": " << desc.MipLevels << ", "
           << "\"Format\": " << desc.Format << ", "
           << "\"Layout\": " << desc.Layout << ", "
           << "\"SampleDesc\": " << AppendTo(desc.SampleDesc) << ", "
           << "\"Flags\": " << desc.Flags << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const ALLOCATOR_RECORD_OPTIONS& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"Flags\": " << desc.Flags << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const D3D12_DEPTH_STENCIL_VALUE& depthStencilValue) {
        std::stringstream ss;
        ss << "{ "
           << "\"Depth\": " << depthStencilValue.Depth << ", "
           << "\"Stencil\": " << depthStencilValue.Stencil << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const FLOAT rgba[4]) {
        std::stringstream ss;
        ss << "{ "
           << "\"R\": " << rgba[0] << ", "
           << "\"G\": " << rgba[1] << ", "
           << "\"B\": " << rgba[2] << ", "
           << "\"A\": " << rgba[3] << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const D3D12_CLEAR_VALUE* clearValue) {
        if (clearValue == nullptr) {
            return "{}";
        }
        std::stringstream ss;
        ss << "{ "
           << "\"Format\": " << clearValue->Format << ", ";

        if (IsDepthFormat(clearValue->Format)) {
            ss << "\"DepthStencil\": " << AppendTo(clearValue->DepthStencil);
        } else {
            ss << "\"Color\": " << AppendTo(clearValue->Color);
        }

        ss << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const DXGI_SAMPLE_DESC& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"Count\": " << desc.Count << ", "
           << "\"Quality\": " << desc.Quality << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const HEAP_DESC& desc) {
        std::stringstream memoryPoolID;
        memoryPoolID << std::hex << TraceEventID(desc.MemoryPool).GetID();

        std::stringstream ss;
        ss << "{ "
           << "\"Size\": " << desc.Size << ", "
           << "\"IsResident\": " << desc.IsResident << ", "
           << "\"MemorySegmentGroup\": " << desc.MemorySegmentGroup << ", "
           << "\"SubAllocatedRefs\": " << desc.SubAllocatedRefs;

        if (desc.MemoryPool != nullptr) {
            ss << ", "
               << "\"MemoryPool\": {"
               << "\"id_ref\": \"0x" << memoryPoolID.str() << "\" }";
        }

        ss << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const RESOURCE_ALLOCATION_DESC& desc) {
        std::stringstream resourceHeapID;
        resourceHeapID << std::hex << TraceEventID(desc.ResourceHeap).GetID();

        std::stringstream ss;
        ss << "{ "
           << "\"Size\": " << desc.Size << ", "
           << "\"HeapOffset\": " << desc.HeapOffset << ", "
           << "\"OffsetFromResource\": " << desc.OffsetFromResource << ", "
           << "\"Method\": " << desc.Method << ", "
           << "\"ResourceHeap\": {"
           << "\"id_ref\": \"0x" << resourceHeapID.str() << "\" }"
           << " }";
        return ss.str();
    }

    // static
    std::string JSONSerializer::AppendTo(const QUERY_RESOURCE_ALLOCATOR_INFO& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"UsedBlockCount\": " << desc.UsedBlockCount << ", "
           << "\"UsedResourceHeapCount\": " << desc.UsedResourceHeapCount << ", "
           << "\"UsedBlockUsage\": " << desc.UsedBlockUsage << ", "
           << "\"UsedResourceHeapUsage\": " << desc.UsedResourceHeapUsage << " }";
        return ss.str();
    }

    std::string JSONSerializer::AppendTo(const ALLOCATOR_MESSAGE& desc) {
        std::stringstream ss;
        ss << "{ "
           << "\"Description\": \"" << desc.Description << "\", "
           << "\"ID\": " << desc.ID << " }";
        return ss.str();
    }

}}  // namespace gpgmm::d3d12
