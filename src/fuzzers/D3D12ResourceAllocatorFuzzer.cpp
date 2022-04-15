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

#include <cstdint>

#include "testing/libfuzzer/libfuzzer_exports.h"

#include <gpgmm_d3d12.h>

namespace {

    ComPtr<gpgmm::d3d12::ResourceAllocator> gResourceAllocator;

}  // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    gpgmm::d3d12::ALLOCATOR_DESC allocatorDesc = {};

    // Populate the device
    ComPtr<ID3D12Device> d3dDevice;
    if (FAILED(D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&d3dDevice)))) {
        return 0;
    }

    allocatorDesc.Device = d3dDevice;

    // Populate the adapter
    LUID adapterLUID = d3dDevice->GetAdapterLuid();
    ComPtr<IDXGIFactory1> dxgiFactory;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory)))) {
        return 0;
    }

    ComPtr<IDXGIFactory4> dxgiFactory4;
    if (FAILED(dxgiFactory.As(&dxgiFactory4))) {
        return 0;
    }

    ComPtr<IDXGIAdapter3> dxgiAdapter;
    if (FAILED(dxgiFactory4->EnumAdapterByLuid(adapterLUID, IID_PPV_ARGS(&dxgiAdapter)))) {
        return 0;
    }

    allocatorDesc.Adapter = dxgiAdapter;

    // Populate the options.
    D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
    if (FAILED(d3dDevice->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch, sizeof(arch)))) {
        return 0;
    }

    allocatorDesc.IsUMA = arch.UMA;

    D3D12_FEATURE_DATA_D3D12_OPTIONS options = {};
    if (FAILED(d3dDevice->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options,
                                              sizeof(options)))) {
        return 0;
    }

    allocatorDesc.ResourceHeapTier = options.ResourceHeapTier;

    if (FAILED(
            gpgmm::d3d12::ResourceAllocator::CreateAllocator(allocatorDesc, &gResourceAllocator))) {
        return 0;
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8) {
        return 0;
    }

    if (gResourceAllocator == nullptr) {
        return 0;
    }

    D3D12_RESOURCE_DESC resourceDesc = {};
    resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    resourceDesc.Alignment = 0;
    resourceDesc.Width = static_cast<uint64_t>(data[0]);
    resourceDesc.Height = 1;
    resourceDesc.DepthOrArraySize = 1;
    resourceDesc.MipLevels = 1;
    resourceDesc.Format = DXGI_FORMAT_UNKNOWN;
    resourceDesc.SampleDesc.Count = 1;
    resourceDesc.SampleDesc.Quality = 0;
    resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    resourceDesc.Flags = D3D12_RESOURCE_FLAG_NONE;

    gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<gpgmm::d3d12::ResourceAllocation> allocation;
    gResourceAllocator->CreateResource(allocationDesc, resourceDesc, D3D12_RESOURCE_STATE_COMMON,
                                       nullptr, &allocation);
    return 0;
}
