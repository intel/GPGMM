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

#include "tests/D3D12Test.h"

#include <gpgmm_d3d12.h>

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"
#include "gpgmm/utils/WindowsUtils.h"

namespace gpgmm::d3d12 {

    D3D12_MESSAGE_SEVERITY GetMessageSeverity(MessageSeverity MessageSeverity) {
        switch (MessageSeverity) {
            case MessageSeverity::kError:
                return D3D12_MESSAGE_SEVERITY_ERROR;
            case MessageSeverity::kWarning:
                return D3D12_MESSAGE_SEVERITY_WARNING;
            case MessageSeverity::kInfo:
                return D3D12_MESSAGE_SEVERITY_INFO;
            case MessageSeverity::kDebug:
                return D3D12_MESSAGE_SEVERITY_MESSAGE;
            default:
                UNREACHABLE();
                return {};
        }
    }

    long GetRefCount(IUnknown* unknown) {
        if (unknown == nullptr) {
            return 0;
        }
        unknown->AddRef();
        return unknown->Release();
    }

    RESOURCE_ALLOCATOR_STATS GetStats(ComPtr<IResourceAllocator> resourceAllocator) {
        RESOURCE_ALLOCATOR_STATS stats = {};
        resourceAllocator->QueryStats(&stats);
        return stats;
    }

    RESIDENCY_MANAGER_STATS GetStats(ComPtr<IResidencyManager> residencyManager) {
        RESIDENCY_MANAGER_STATS stats = {};
        residencyManager->QueryStats(&stats);
        return stats;
    }

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

        DXGI_ADAPTER_DESC adapterDesc;
        ASSERT_SUCCEEDED(mAdapter->GetDesc(&adapterDesc));

        DebugLog() << "GPU: " << WCharToUTF8(adapterDesc.Description)
                   << " (device: " << ToHexStr(adapterDesc.DeviceId)
                   << ", vendor: " << ToHexStr(adapterDesc.VendorId) << ")";
        DebugLog() << "System memory: "
                   << GPGMM_BYTES_TO_GB(adapterDesc.SharedSystemMemory +
                                        adapterDesc.DedicatedSystemMemory)
                   << " GBs"
                   << " (" << GPGMM_BYTES_TO_GB(adapterDesc.DedicatedSystemMemory)
                   << " dedicated) ";
        DebugLog() << "GPU memory: " << GPGMM_BYTES_TO_GB(adapterDesc.DedicatedVideoMemory)
                   << " GBs.";

        Caps* capsPtr = nullptr;
        ASSERT_SUCCEEDED(Caps::CreateCaps(mDevice.Get(), mAdapter.Get(), &capsPtr));
        mCaps.reset(capsPtr);

        DebugLog() << "Unified memory: " << ((mCaps->IsAdapterUMA()) ? "yes" : "no")
                   << ((mCaps->IsAdapterCacheCoherentUMA()) ? " (cache-coherent)" : "");

        DebugLog() << "Max resource size: " << GPGMM_BYTES_TO_GB(mCaps->GetMaxResourceSize())
                   << " GBs";
        DebugLog() << "Max resource heap tier: " << mCaps->GetMaxResourceHeapTierSupported();
        DebugLog() << "Max resource heap size: "
                   << GPGMM_BYTES_TO_GB(mCaps->GetMaxResourceHeapSize()) << " GBs";
        DebugLog() << "Creation of non-resident heaps: "
                   << ((mCaps->IsCreateHeapNotResidentSupported()) ? "Supported" : "Not supported");

        // Format the output trace file as <test suite>.<test>.
        const testing::TestInfo* const testInfoPtr =
            ::testing::UnitTest::GetInstance()->current_test_info();
        ASSERT_TRUE(testInfoPtr != nullptr);

        mTraceFile = std::string(std::string(testInfoPtr->test_suite_name()) + "_" +
                                 std::string(testInfoPtr->name()) + ".json");
    }

    void D3D12TestBase::TearDown() {
        GPGMMTestBase::TearDown();
    }

    ALLOCATOR_DESC D3D12TestBase::CreateBasicAllocatorDesc() const {
        ALLOCATOR_DESC desc = {};
        desc.ResourceHeapTier = mCaps->GetMaxResourceHeapTierSupported();
        desc.MinLogLevel = GetMessageSeverity(GetLogLevel());

        if (IsDumpEventsEnabled()) {
            desc.RecordOptions.Flags |= RECORD_FLAGS_ALL;
            desc.MinRecordLevel = desc.MinLogLevel;
            desc.RecordOptions.UseDetailedTimingEvents = true;
            desc.RecordOptions.TraceFile = mTraceFile.c_str();
        }

        return desc;
    }

    RESIDENCY_DESC D3D12TestBase::CreateBasicResidencyDesc() const {
        RESIDENCY_DESC desc = {};
        desc.MinLogLevel = GetMessageSeverity(GetLogLevel());

        if (IsDumpEventsEnabled()) {
            desc.RecordOptions.Flags |= RECORD_FLAGS_ALL;
            desc.MinRecordLevel = desc.MinLogLevel;
            desc.RecordOptions.UseDetailedTimingEvents = true;
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
#if defined(GPGMM_DISABLE_SIZE_CACHE)
        return false;
#else
        return true;
#endif
    }

}  // namespace gpgmm::d3d12
