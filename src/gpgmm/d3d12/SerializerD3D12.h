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

#ifndef GPGMM_D3D12_SERIALIZERD3D12_H_
#define GPGMM_D3D12_SERIALIZERD3D12_H_

#include "gpgmm/Serializer.h"
#include "gpgmm/common/Log.h"
#include "gpgmm/d3d12/d3d12_platform.h"

namespace gpgmm { namespace d3d12 {

    // Forward declare backend types.
    struct ALLOCATION_DESC;
    struct ALLOCATOR_DESC;
    struct ALLOCATOR_MESSAGE;
    struct ALLOCATOR_RECORD_OPTIONS;
    struct CREATE_RESOURCE_DESC;
    struct HEAP_INFO;
    struct RESOURCE_ALLOCATION_INFO;

    class Serializer : public gpgmm::Serializer {
      public:
        static JSONDict Serialize(const ALLOCATOR_DESC& desc);
        static JSONDict Serialize(const CREATE_RESOURCE_DESC& desc);
        static JSONDict Serialize(const ALLOCATION_DESC& desc);
        static JSONDict Serialize(const D3D12_RESOURCE_DESC& desc);
        static JSONDict Serialize(const HEAP_INFO& desc);
        static JSONDict Serialize(const RESOURCE_ALLOCATION_INFO& desc);
        static JSONDict Serialize(const ALLOCATOR_MESSAGE& desc);

      private:
        static JSONDict Serialize(const ALLOCATOR_RECORD_OPTIONS& desc);
        static JSONDict Serialize(const D3D12_DEPTH_STENCIL_VALUE& depthStencilValue);
        static JSONDict Serialize(const FLOAT rgba[4]);
        static JSONDict Serialize(const D3D12_CLEAR_VALUE* clearValue);
        static JSONDict Serialize(const DXGI_SAMPLE_DESC& desc);
    };

    template <typename T>
    static void RecordEvent(const char* name, const T& desc) {
        return gpgmm::RecordEvent<T, Serializer>(name, desc);
    }

    template <typename... Args>
    static void RecordMessage(const LogSeverity& severity, const char* name, const Args&... args) {
        return gpgmm::RecordCommon<ALLOCATOR_MESSAGE, Serializer>(severity, name, args...);
    }

    template <typename T, typename... Args>
    static void RecordEvent(const char* name, const Args&... args) {
        return gpgmm::RecordEvent<T, Serializer>(name, args...);
    }

    template <typename T, typename DescT>
    static void RecordEvent(const char* name, T* objPtr, const DescT& desc) {
        return gpgmm::RecordEvent<T, DescT, Serializer>(name, objPtr, desc);
    }

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_SERIALIZERD3D12_H_
