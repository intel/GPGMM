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

#ifndef GPGMM_D3D12_DEBUGD3D12_H_
#define GPGMM_D3D12_DEBUGD3D12_H_

#include "gpgmm/Debug.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"

namespace gpgmm { namespace d3d12 {

    template <typename T, typename... Args>
    static void RecordCall(const char* name, const Args&... args) {
        return gpgmm::RecordCall<T, JSONSerializer>(name, args...);
    }

    template <typename T, typename DescT>
    static void RecordObject(const char* name, T* objPtr, const DescT& desc) {
        return gpgmm::RecordObject<T, DescT, JSONSerializer>(name, objPtr, desc);
    }

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_DEBUGD3D12_H_
