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

#include "gpgmm/d3d12/CapsD3D12.h"

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/Log.h"
#include "gpgmm/utils/Utils.h"
#include "gpgmm/utils/WindowsUtils.h"

#include <memory>

namespace gpgmm::d3d12 {

    HRESULT SetMaxResourceSize(ID3D12Device* pDevice, uint64_t* pSizeOut) {
        ASSERT(pSizeOut);
        D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT feature = {};
        GPGMM_RETURN_IF_FAILED(
            pDevice->CheckFeatureSupport(D3D12_FEATURE_GPU_VIRTUAL_ADDRESS_SUPPORT, &feature,
                                         sizeof(D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT)),
            pDevice);
        // Check for overflow.
        if (feature.MaxGPUVirtualAddressBitsPerResource == 0 ||
            feature.MaxGPUVirtualAddressBitsPerResource > GetNumOfBits<uint64_t>()) {
            return E_FAIL;
        }

        *pSizeOut = (1ull << (feature.MaxGPUVirtualAddressBitsPerResource - 1)) - 1;
        return S_OK;
    }

    HRESULT SetMaxResourceHeapSize(ID3D12Device* pDevice, uint64_t* pSizeOut) {
        ASSERT(pSizeOut);
        D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT feature = {};
        GPGMM_RETURN_IF_FAILED(
            pDevice->CheckFeatureSupport(D3D12_FEATURE_GPU_VIRTUAL_ADDRESS_SUPPORT, &feature,
                                         sizeof(D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT)),
            pDevice);
        // Check for overflow.
        if (feature.MaxGPUVirtualAddressBitsPerProcess == 0 ||
            feature.MaxGPUVirtualAddressBitsPerProcess > GetNumOfBits<uint64_t>()) {
            return E_FAIL;
        }

        *pSizeOut = (1ull << (feature.MaxGPUVirtualAddressBitsPerProcess - 1)) - 1;
        return S_OK;
    }

    HRESULT SetCreateHeapNotResidentSupported(ID3D12Device* pDevice,
                                              bool* createHeapNotResidencySupported) {
        ASSERT(createHeapNotResidencySupported);
        *createHeapNotResidencySupported = false;

        // Only Windows 10 Build 20348 and later support creating non-resident heaps.
        // ID3D12Device8 is required to be defined in Windows 10 Build 20348 or newer builds.
#ifdef __ID3D12Device8_FWD_DEFINED__
        D3D12_FEATURE_DATA_D3D12_OPTIONS7 options7 = {};
        if (SUCCEEDED(pDevice->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS7, &options7,
                                                   sizeof(options7)))) {
            *createHeapNotResidencySupported = true;
        }
#endif
        return S_OK;
    }

    HRESULT SetMaxResourceHeapTierSupported(ID3D12Device* pDevice,
                                            D3D12_RESOURCE_HEAP_TIER* maxResourceHeapTierOut) {
        ASSERT(maxResourceHeapTierOut);
        D3D12_FEATURE_DATA_D3D12_OPTIONS options = {};
        GPGMM_RETURN_IF_FAILED(
            pDevice->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options, sizeof(options)),
            pDevice);
        *maxResourceHeapTierOut = options.ResourceHeapTier;
        return S_OK;
    }

    // static
    HRESULT Caps::CreateCaps(ID3D12Device* pDevice, IUnknown* pAdapter, Caps** ppCapsOut) {
        ASSERT(pDevice);

        std::unique_ptr<Caps> caps(new Caps());

        // Load device-specific capabilities.
        GPGMM_RETURN_IF_FAILED(SetMaxResourceSize(pDevice, &caps->mMaxResourceSize));
        GPGMM_RETURN_IF_FAILED(SetMaxResourceHeapSize(pDevice, &caps->mMaxResourceHeapSize));
        GPGMM_RETURN_IF_FAILED(
            SetMaxResourceHeapTierSupported(pDevice, &caps->mMaxResourceHeapTier));
        GPGMM_RETURN_IF_FAILED(
            SetCreateHeapNotResidentSupported(pDevice, &caps->mIsCreateHeapNotResidentSupported));

        // Load adapter-specific capabilities.
        D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
        GPGMM_RETURN_IF_FAILED(
            pDevice->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch, sizeof(arch)), pDevice);
        caps->mIsAdapterUMA = arch.UMA;
        caps->mIsAdapterCacheCoherentUMA = arch.CacheCoherentUMA;

        if (pAdapter != nullptr) {
            ComPtr<IDXGIAdapter> dxgiAdapter;
            GPGMM_RETURN_IF_FAILED(pAdapter->QueryInterface(IID_PPV_ARGS(&dxgiAdapter)));

            DXGI_ADAPTER_DESC adapterDesc;
            GPGMM_RETURN_IF_FAILED(dxgiAdapter->GetDesc(&adapterDesc));

            caps->mSharedSegmentSize = adapterDesc.SharedSystemMemory;
            caps->mDedicatedSegmentSize = adapterDesc.DedicatedVideoMemory;

            // D3D12 has no feature to detect support and must be set manually.
            if (adapterDesc.VendorId == static_cast<uint32_t>(GPUVendor::kIntel_Vendor)) {
                caps->mIsResourceAllocationWithinCoherent = true;
            }
        } else {
            WarnLog()
                << "Adapter was left unspecified. Device capabilities may not be fully detected.";
        }

        if (ppCapsOut != nullptr) {
            *ppCapsOut = caps.release();
        }

        return S_OK;
    }

    uint64_t Caps::GetMaxResourceSize() const {
        return mMaxResourceSize;
    }

    uint64_t Caps::GetMaxResourceHeapSize() const {
        return mMaxResourceHeapSize;
    }

    uint64_t Caps::GetMaxSegmentSize(DXGI_MEMORY_SEGMENT_GROUP heapSegment) const {
        if (mIsAdapterUMA) {
            return mSharedSegmentSize;
        }

        switch (heapSegment) {
            case DXGI_MEMORY_SEGMENT_GROUP_LOCAL:
                return mDedicatedSegmentSize;

            case DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL:
                return mSharedSegmentSize;

            default:
                UNREACHABLE();
                return kInvalidSize;
        }
    }

    bool Caps::IsCreateHeapNotResidentSupported() const {
        return mIsCreateHeapNotResidentSupported;
    }

    bool Caps::IsResourceAllocationWithinCoherent() const {
        return mIsResourceAllocationWithinCoherent;
    }

    bool Caps::IsAdapterUMA() const {
        return mIsAdapterUMA;
    }

    bool Caps::IsAdapterCacheCoherentUMA() const {
        return mIsAdapterCacheCoherentUMA;
    }

    D3D12_RESOURCE_HEAP_TIER Caps::GetMaxResourceHeapTierSupported() const {
        return mMaxResourceHeapTier;
    }

}  // namespace gpgmm::d3d12
