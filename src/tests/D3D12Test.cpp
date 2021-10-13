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

#include "src/tests/D3D12Test.h"

#include <gpgmm_d3d12.h>

namespace gpgmm { namespace d3d12 {

    void D3D12TestBase::SetUp() {
        GPGMMTestBase::SetUp();

        D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&mDevice));
        ASSERT_NE(mDevice.Get(), nullptr);

        LUID adapterLUID = mDevice->GetAdapterLuid();
        ComPtr<IDXGIFactory1> dxgiFactory;
        CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory));
        ASSERT_NE(dxgiFactory.Get(), nullptr);

        ComPtr<IDXGIFactory4> dxgiFactory4;
        dxgiFactory.As(&dxgiFactory4);
        ASSERT_NE(dxgiFactory4.Get(), nullptr);

        dxgiFactory4->EnumAdapterByLuid(adapterLUID, IID_PPV_ARGS(&mAdapter));
        ASSERT_NE(mAdapter.Get(), nullptr);

        D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
        mDevice->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch, sizeof(arch));
        mIsUMA = arch.UMA;

        D3D12_FEATURE_DATA_D3D12_OPTIONS options = {};
        mDevice->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options, sizeof(options));
        mResourceHeapTier = options.ResourceHeapTier;
    }

    void D3D12TestBase::TearDown() {
        GPGMMTestBase::TearDown();
        // TODO
    }

    ALLOCATOR_DESC D3D12TestBase::CreateBasicAllocatorDesc() const {
        ALLOCATOR_DESC desc = {};
        desc.Adapter = mAdapter;
        desc.Device = mDevice;
        desc.IsUMA = mIsUMA;
        desc.ResourceHeapTier = mResourceHeapTier;
        return desc;
    }

}}  // namespace gpgmm::d3d12
