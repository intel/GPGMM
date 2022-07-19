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

#include "D3D12Fuzzer.h"

uint64_t UInt8ToUInt64(const uint8_t* src) {
    uint64_t dst;
    memcpy(&dst, src, sizeof(uint64_t));
    return dst;
}

HRESULT CreateAllocatorDesc(gpgmm::d3d12::ALLOCATOR_DESC* allocatorDesc) {
    gpgmm::d3d12::ALLOCATOR_DESC allocatorDescOut = {};

    // Populate the device
    ComPtr<ID3D12Device> d3dDevice;
    if (FAILED(D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&d3dDevice)))) {
        return E_FAIL;
    }

    allocatorDescOut.Device = d3dDevice;

    // Populate the adapter
    LUID adapterLUID = d3dDevice->GetAdapterLuid();
    ComPtr<IDXGIFactory1> dxgiFactory;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory)))) {
        return E_FAIL;
    }

    ComPtr<IDXGIFactory4> dxgiFactory4;
    if (FAILED(dxgiFactory.As(&dxgiFactory4))) {
        return E_FAIL;
    }

    ComPtr<IDXGIAdapter3> dxgiAdapter;
    if (FAILED(dxgiFactory4->EnumAdapterByLuid(adapterLUID, IID_PPV_ARGS(&dxgiAdapter)))) {
        return E_FAIL;
    }

    allocatorDescOut.Adapter = dxgiAdapter;

    // Populate the options.
    D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
    if (FAILED(d3dDevice->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch, sizeof(arch)))) {
        return E_FAIL;
    }

    allocatorDescOut.IsUMA = arch.UMA;

    D3D12_FEATURE_DATA_D3D12_OPTIONS options = {};
    if (FAILED(d3dDevice->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options,
                                              sizeof(options)))) {
        return E_FAIL;
    }

    allocatorDescOut.ResourceHeapTier = options.ResourceHeapTier;

    *allocatorDesc = allocatorDescOut;
    return S_OK;
}

D3D12_RESOURCE_DESC CreateBufferDesc(uint64_t width, uint64_t alignment) {
    D3D12_RESOURCE_DESC resourceDesc = {};
    resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    resourceDesc.Alignment = 0;
    resourceDesc.Width = width;
    resourceDesc.Height = 1;
    resourceDesc.DepthOrArraySize = 1;
    resourceDesc.MipLevels = 1;
    resourceDesc.Format = DXGI_FORMAT_UNKNOWN;
    resourceDesc.SampleDesc.Count = 1;
    resourceDesc.SampleDesc.Quality = 0;
    resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    resourceDesc.Flags = D3D12_RESOURCE_FLAG_NONE;
    return resourceDesc;
}
