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

#include "gpgmm/GPUInfo.h"
#include "gpgmm/d3d12/d3d12_platform.h"

namespace gpgmm { namespace d3d12 {

    class Caps {
      public:
        static HRESULT CreateCaps(ID3D12Device* device, IDXGIAdapter* adapter, Caps** capsOut);

        // On some GPUs, accessing different sub-allocations from the same resource with
        // different queues is always coherent.
        bool IsSuballocationWithinResourceCoherent() const;

      private:
        Caps() = default;

        bool mIsSuballocationWithinResourceCoherent = false;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_CAPSD3D12_H_
