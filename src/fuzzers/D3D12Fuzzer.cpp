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

#include "D3D12Fuzzer.h"

uint64_t UInt8ToUInt64(const uint8_t* src) {
    uint64_t dst;
    memcpy_s(&dst, sizeof(uint64_t), src, sizeof(uint8_t));
    return dst;
}

HRESULT CreateResourceAllocatorDesc(gpgmm::d3d12::RESOURCE_ALLOCATOR_DESC* pAllocatorDesc,
                                    ID3D12Device** ppDeviceOut,
                                    IDXGIAdapter3** ppAdapterOut) {
    gpgmm::d3d12::RESOURCE_ALLOCATOR_DESC allocatorDescOut = {};

    // Populate the device
    if (FAILED(D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(ppDeviceOut)))) {
        return E_FAIL;
    }

    // Populate the adapter
    LUID adapterLUID = (*ppDeviceOut)->GetAdapterLuid();
    ComPtr<IDXGIFactory1> dxgiFactory;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory)))) {
        return E_FAIL;
    }

    ComPtr<IDXGIFactory4> dxgiFactory4;
    if (FAILED(dxgiFactory.As(&dxgiFactory4))) {
        return E_FAIL;
    }

    if (FAILED(dxgiFactory4->EnumAdapterByLuid(adapterLUID, IID_PPV_ARGS(ppAdapterOut)))) {
        return E_FAIL;
    }

    // Configure options
    allocatorDescOut.MinLogLevel = D3D12_MESSAGE_SEVERITY_MESSAGE;

    if (pAllocatorDesc != nullptr) {
        *pAllocatorDesc = allocatorDescOut;
    }

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
