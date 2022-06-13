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

#include "tests/D3D12Test.h"

#include <gpgmm_d3d12.h>

namespace gpgmm { namespace d3d12 {

    void D3D12TestBase::SetUp() {
        GPGMMTestBase::SetUp();

        ComPtr<ID3D12Debug> debugController;
        ASSERT_SUCCEEDED(D3D12GetDebugInterface(IID_PPV_ARGS(&debugController)));
        debugController->EnableDebugLayer();

        ASSERT_SUCCEEDED(
            D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&mDevice)));
        ASSERT_NE(mDevice.Get(), nullptr);

        LUID adapterLUID = mDevice->GetAdapterLuid();
        ComPtr<IDXGIFactory1> dxgiFactory;
        ASSERT_SUCCEEDED(CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory)));
        ASSERT_NE(dxgiFactory.Get(), nullptr);

        ComPtr<IDXGIFactory4> dxgiFactory4;
        ASSERT_SUCCEEDED(dxgiFactory.As(&dxgiFactory4));
        ASSERT_NE(dxgiFactory4.Get(), nullptr);

        ASSERT_SUCCEEDED(dxgiFactory4->EnumAdapterByLuid(adapterLUID, IID_PPV_ARGS(&mAdapter)));
        ASSERT_NE(mAdapter.Get(), nullptr);

        D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
        ASSERT_SUCCEEDED(
            mDevice->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch, sizeof(arch)));
        mIsUMA = arch.UMA;

        D3D12_FEATURE_DATA_D3D12_OPTIONS options = {};
        ASSERT_SUCCEEDED(
            mDevice->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options, sizeof(options)));
        mResourceHeapTier = options.ResourceHeapTier;
    }

    void D3D12TestBase::TearDown() {
        GPGMMTestBase::TearDown();
    }

    ALLOCATOR_DESC D3D12TestBase::CreateBasicAllocatorDesc(bool isPrefetchAllowed) const {
        ALLOCATOR_DESC desc = {};

        // Required parameters.
        desc.Adapter = mAdapter;
        desc.Device = mDevice;
        desc.IsUMA = mIsUMA;
        desc.ResourceHeapTier = mResourceHeapTier;

        // Pre-fetching is enabled by default. However for testing purposes, pre-fetching changes
        // expectations that check GPU memory usage and needs to be tested in isolation.
        if (!isPrefetchAllowed) {
            desc.Flags |= ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH;
        }

#if defined(NDEBUG)
        desc.MinLogLevel = D3D12_MESSAGE_SEVERITY_WARNING;
#else
        desc.MinLogLevel = D3D12_MESSAGE_SEVERITY_MESSAGE;
        desc.RecordOptions.UseDetailedTimingEvents = true;
#endif

        if (IsDumpResourceAllocatorEnabled()) {
            desc.RecordOptions.Flags |= ALLOCATOR_RECORD_FLAG_ALL_EVENTS;
            desc.RecordOptions.MinMessageLevel = desc.MinLogLevel;
        }

        return desc;
    }

    // static
    D3D12_RESOURCE_DESC D3D12TestBase::CreateBasicBufferDesc(uint64_t width, uint64_t alignment) {
        D3D12_RESOURCE_DESC resourceDesc;
        resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        resourceDesc.Alignment = alignment;
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

    // static
    D3D12_RESOURCE_DESC D3D12TestBase::CreateBasicTextureDesc(DXGI_FORMAT format,
                                                              uint64_t width,
                                                              uint32_t height,
                                                              uint32_t sampleCount,
                                                              uint64_t alignment) {
        D3D12_RESOURCE_DESC resourceDesc;
        resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
        resourceDesc.Alignment = alignment;
        resourceDesc.Width = width;
        resourceDesc.Height = height;
        resourceDesc.DepthOrArraySize = 1;
        resourceDesc.MipLevels = 1;
        resourceDesc.Format = format;
        resourceDesc.SampleDesc.Count = sampleCount;
        resourceDesc.SampleDesc.Quality = 0;
        resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;

        // A multisampled resource must have either D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET or
        // D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL set.
        resourceDesc.Flags =
            (sampleCount > 1) ? D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET : D3D12_RESOURCE_FLAG_NONE;

        return resourceDesc;
    }

    // static
    std::vector<MEMORY_ALLOCATION_EXPECT> D3D12TestBase::GenerateBufferAllocations() {
        return GPGMMTestBase::GenerateTestAllocations(D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT);
    }

    bool D3D12TestBase::IsSizeCacheEnabled() const {
#if defined(GPGMM_ENABLE_SIZE_CACHE)
        return true;
#else
        return false;
#endif
    }

}}  // namespace gpgmm::d3d12
