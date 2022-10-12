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

#include <d3d12.h>
#include <dxgi1_4.h>
#include <wrl.h>

#include <gpgmm_d3d12.h>

HRESULT Init() {
    Microsoft::WRL::ComPtr<IDXGIAdapter3> adapter3;
    Microsoft::WRL::ComPtr<ID3D12Device> device;
    HRESULT hr = D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device));
    if (FAILED(hr)) {
        return hr;
    }

    LUID adapterLUID = device->GetAdapterLuid();
    Microsoft::WRL::ComPtr<IDXGIFactory1> dxgiFactory;
    hr = CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory));
    if (FAILED(hr)) {
        return hr;
    }

    Microsoft::WRL::ComPtr<IDXGIFactory4> dxgiFactory4;
    hr = dxgiFactory.As(&dxgiFactory4);
    if (FAILED(hr)) {
        return hr;
    }

    hr = dxgiFactory4->EnumAdapterByLuid(adapterLUID, IID_PPV_ARGS(&adapter3));
    if (FAILED(hr)) {
        return hr;
    }

    D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
    hr = device->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch, sizeof(arch));
    if (FAILED(hr)) {
        return hr;
    }

    D3D12_FEATURE_DATA_D3D12_OPTIONS options = {};
    hr = device->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options, sizeof(options));
    if (FAILED(hr)) {
        return hr;
    }

    gpgmm::d3d12::ALLOCATOR_DESC desc = {};
    desc.Adapter = adapter3.Get();
    desc.Device = device.Get();
    desc.ResourceHeapTier = options.ResourceHeapTier;

    Microsoft::WRL::ComPtr<gpgmm::d3d12::IResourceAllocator> resourceAllocator;
    hr = gpgmm::d3d12::CreateResourceAllocator(desc, &resourceAllocator, nullptr);
    if (FAILED(hr)) {
        return hr;
    }

    return S_OK;
}

int main(int argc, const char* argv[]) {
    HRESULT hr = Init();
    if (FAILED(hr)) {
        return hr;
    }
    return 0;
}
