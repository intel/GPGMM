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

#ifndef GPGMM_D3D12_JSONSERIALIZERD3D12_H_
#define GPGMM_D3D12_JSONSERIALIZERD3D12_H_

#include "gpgmm/common/JSONSerializer.h"
#include "gpgmm/d3d12/D3D12Platform.h"

#include <gpgmm_d3d12.h>

namespace gpgmm::d3d12 {

    struct RESOURCE_ALLOCATION_DESC;

    struct CREATE_RESOURCE_DESC {
        const ALLOCATION_DESC& allocationDescriptor;
        const D3D12_RESOURCE_DESC& resourceDescriptor;
        D3D12_RESOURCE_STATES initialResourceState;
        const D3D12_CLEAR_VALUE* clearValue;
    };

    struct CREATE_HEAP_DESC {
        const RESIDENCY_HEAP_DESC& HeapDescriptor;
        ID3D12Pageable* Pageable;
    };

    struct EXECUTE_COMMAND_LISTS_DESC {
        IResidencyList* const* ResidencyLists;
        uint32_t Count;
    };

    class JSONSerializer final : public gpgmm::JSONSerializer {
      public:
        static JSONDict Serialize();
        static JSONDict Serialize(const RESOURCE_ALLOCATOR_DESC& desc);
        static JSONDict Serialize(const CREATE_RESOURCE_DESC& desc);
        static JSONDict Serialize(const ALLOCATION_DESC& desc);
        static JSONDict Serialize(const D3D12_RESOURCE_DESC& desc);
        static JSONDict Serialize(const CREATE_HEAP_DESC& desc);
        static JSONDict Serialize(const RESIDENCY_HEAP_DESC& desc);
        static JSONDict Serialize(const RESIDENCY_HEAP_INFO& info);
        static JSONDict Serialize(const RESOURCE_ALLOCATION_DESC& desc);
        static JSONDict Serialize(const RESOURCE_ALLOCATION_INFO& info);
        static JSONDict Serialize(const EXECUTE_COMMAND_LISTS_DESC& desc);
        static JSONDict Serialize(const RESIDENCY_MANAGER_DESC& desc);
        static JSONDict Serialize(const RECORD_OPTIONS& desc);

      private:
        static JSONDict Serialize(const D3D12_DEPTH_STENCIL_VALUE& depthStencilValue);
        static JSONDict Serialize(const FLOAT rgba[4]);
        static JSONDict Serialize(const D3D12_CLEAR_VALUE* clearValue);
        static JSONDict Serialize(const DXGI_SAMPLE_DESC& desc);
        static JSONDict Serialize(const D3D12_HEAP_DESC& desc);
        static JSONDict Serialize(const D3D12_HEAP_PROPERTIES& desc);
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_JSONSERIALIZERD3D12_H_
