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

#include <cmath>
#include <memory>

namespace gpgmm::d3d12 {

    HRESULT SetMaxResourceSize(ID3D12Device* device, uint64_t* sizeOut) {
        D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT feature = {};
        ReturnIfFailed(
            device->CheckFeatureSupport(D3D12_FEATURE_GPU_VIRTUAL_ADDRESS_SUPPORT, &feature,
                                        sizeof(D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT)));

        *sizeOut = std::pow(2, feature.MaxGPUVirtualAddressBitsPerResource) - 1;
        return S_OK;
    }

    HRESULT SetMaxResourceHeapSize(ID3D12Device* device, uint64_t* sizeOut) {
        D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT feature = {};
        ReturnIfFailed(
            device->CheckFeatureSupport(D3D12_FEATURE_GPU_VIRTUAL_ADDRESS_SUPPORT, &feature,
                                        sizeof(D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT)));

        *sizeOut = std::pow(2, feature.MaxGPUVirtualAddressBitsPerProcess) - 1;
        return S_OK;
    }

    HRESULT SetCreateHeapNotResidentSupported(ID3D12Device* device,
                                              bool* createHeapNotResidencySupported) {
        *createHeapNotResidencySupported = false;

        // Only Windows 10 Build 20348 and later support creating non-resident heaps.
#ifdef D3D12_FEATURE_D3D12_OPTIONS7
        D3D12_FEATURE_DATA_D3D12_OPTIONS7 options7 = {};
        if (SUCCEEDED(device->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS7, &options7,
                                                  sizeof(options7)))) {
            *createHeapNotResidencySupported = true;
        }
#endif
        return S_OK;
    }

    // static
    HRESULT Caps::CreateCaps(ID3D12Device* device, IDXGIAdapter* adapter, Caps** capsOut) {
        DXGI_ADAPTER_DESC adapterDesc;
        ReturnIfFailed(adapter->GetDesc(&adapterDesc));

        std::unique_ptr<Caps> caps(new Caps());
        ReturnIfFailed(SetMaxResourceSize(device, &caps->mMaxResourceSize));
        ReturnIfFailed(SetMaxResourceHeapSize(device, &caps->mMaxResourceHeapSize));
        ReturnIfFailed(
            SetCreateHeapNotResidentSupported(device, &caps->mIsCreateHeapNotResidentSupported));

        // D3D12 has no feature to detect support and must be set manually.
        if (adapterDesc.VendorId == kIntel_VkVendor) {
            caps->mIsResourceAccessAlwaysCoherent = true;
        }

        *capsOut = caps.release();
        return S_OK;
    }

    uint64_t Caps::GetMaxResourceSize() const {
        return mMaxResourceSize;
    }

    uint64_t Caps::GetMaxResourceHeapSize() const {
        return mMaxResourceHeapSize;
    }

    bool Caps::IsCreateHeapNotResidentSupported() const {
        return mIsCreateHeapNotResidentSupported;
    }

    bool Caps::IsResourceAccessAlwaysCoherent() const {
        return mIsResourceAccessAlwaysCoherent;
    }

}  // namespace gpgmm::d3d12
