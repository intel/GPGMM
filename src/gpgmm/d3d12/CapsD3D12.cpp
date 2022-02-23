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

#include "gpgmm/d3d12/CapsD3D12.h"

#include "gpgmm/d3d12/ErrorD3D12.h"

#include <memory>

namespace gpgmm { namespace d3d12 {

    // static
    HRESULT Caps::CreateCaps(ID3D12Device* device, IDXGIAdapter* adapter, Caps** capsOut) {
        DXGI_ADAPTER_DESC adapterDesc;
        ReturnIfFailed(adapter->GetDesc(&adapterDesc));

        Caps* caps = new Caps();
        // Intel GPUs are always coherent.
        if (adapterDesc.VendorId == GPUVendor::kIntel_VkVendor) {
            caps->mIsSuballocationWithinResourceCoherent = true;
        }

        *capsOut = caps;
        return S_OK;
    }

    bool Caps::IsSuballocationWithinResourceCoherent() const {
        return mIsSuballocationWithinResourceCoherent;
    }

}}  // namespace gpgmm::d3d12
