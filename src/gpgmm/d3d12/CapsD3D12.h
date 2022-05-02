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

#ifndef GPGMM_D3D12_CAPSD3D12_H_
#define GPGMM_D3D12_CAPSD3D12_H_

#include "gpgmm/common/GPUInfo.h"
#include "gpgmm/d3d12/d3d12_platform.h"

#include <cstdint>

namespace gpgmm { namespace d3d12 {

    class Caps {
      public:
        static HRESULT CreateCaps(ID3D12Device* device, IDXGIAdapter* adapter, Caps** capsOut);

        // Largest resource size that this device can make available.
        uint64_t GetMaxResourceSize() const;

        // Largest resource heap that this device can make available.
        uint64_t GetMaxResourceHeapSize() const;

      private:
        Caps() = default;

        uint64_t mMaxResourceSize = 0;
        uint64_t mMaxResourceHeapSize = 0;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_CAPSD3D12_H_
