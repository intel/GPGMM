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

#ifndef GPGMM_D3D12_JSONSERIALIZERD3D12_H_
#define GPGMM_D3D12_JSONSERIALIZERD3D12_H_

#include "src/ObjectSerializer.h"

#include "src/d3d12/d3d12_platform.h"

namespace gpgmm { namespace d3d12 {

    struct ALLOCATION_DESC;
    struct ALLOCATOR_DESC;
    struct ALLOCATOR_RECORD_OPTIONS;

    struct CREATE_RESOURCE_DESC {
        const ALLOCATION_DESC& allocationDescriptor;
        const D3D12_RESOURCE_DESC& resourceDescriptor;
        D3D12_RESOURCE_STATES initialUsage;
        const D3D12_CLEAR_VALUE* clearValue;
    };

    class JSONSerializer : public ObjectSerializer<JSONSerializer> {
      public:
        std::string AppendTo(const ALLOCATOR_DESC& desc);
        std::string AppendTo(const CREATE_RESOURCE_DESC& desc);
        std::string AppendTo(const ALLOCATION_DESC& desc);
        std::string AppendTo(const D3D12_RESOURCE_DESC& desc);

      private:
        std::string AppendTo(const ALLOCATOR_RECORD_OPTIONS& desc);
        std::string AppendTo(const D3D12_DEPTH_STENCIL_VALUE& depthStencilValue);
        std::string AppendTo(const FLOAT rgba[4]);
        std::string AppendTo(const D3D12_CLEAR_VALUE* clearValue);
        std::string AppendTo(const DXGI_SAMPLE_DESC& desc);
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_JSONSERIALIZERD3D12_H_
