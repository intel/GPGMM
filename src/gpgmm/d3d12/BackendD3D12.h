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

#ifndef SRC_GPGMM_D3D12_BACKEND3D12_H_
#define SRC_GPGMM_D3D12_BACKEND3D12_H_

#include "gpgmm/common/Backend.h"

namespace gpgmm::d3d12 {

    class ResourceAllocation;

    struct BackendTraits {
        using AllocationType = ResourceAllocation;
    };

    template <typename T>
    auto ToBackend(T&& common) -> decltype(gpgmm::ToBackend<BackendTraits>(common)) {
        return gpgmm::ToBackend<BackendTraits>(common);
    }

}  // namespace gpgmm::d3d12

#endif
