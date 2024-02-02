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

#ifndef SRC_TESTS_D3D12TEST_H_
#define SRC_TESTS_D3D12TEST_H_

#include "tests/GPGMMTest.h"

#include <memory>
#include <string>
#include <vector>

#include <dxgi1_4.h>
#include <gpgmm_d3d12.h>

#include "gpgmm/d3d12/D3D12Platform.h"

#define ASSERT_FAILED(expr) ASSERT_TRUE(FAILED(expr))
#define ASSERT_SUCCEEDED(expr) ASSERT_TRUE(SUCCEEDED(expr))

#define EXPECT_FAILED(expr) EXPECT_TRUE(FAILED(expr))
#define EXPECT_SUCCEEDED(expr) EXPECT_TRUE(SUCCEEDED(expr))

#define EXPECT_EQUAL_WSTR(wstr1, wstr2) EXPECT_FALSE(wcscmp(wstr1, wstr2))

#define EXPECT_REFCOUNT_EQ(expr, count) EXPECT_EQ(gpgmm::d3d12::GetRefCount(expr), count)

namespace gpgmm::d3d12 {

    class Caps;

    D3D12_MESSAGE_SEVERITY GetMessageSeverity(MessageSeverity MessageSeverity);
    long GetRefCount(IUnknown* unknown);

    RESOURCE_ALLOCATOR_STATS GetStats(ComPtr<IResourceAllocator> resourceAllocator);
    RESIDENCY_MANAGER_STATS GetStats(ComPtr<IResidencyManager> residencyManager);

    class D3D12TestBase : public GPGMMTestBase {
      public:
        void SetUp();
        void TearDown();

        RESIDENCY_MANAGER_DESC CreateBasicResidencyDesc() const;
        RESOURCE_ALLOCATOR_DESC CreateBasicAllocatorDesc() const;

        static D3D12_RESOURCE_DESC CreateBasicBufferDesc(uint64_t width, uint64_t alignment = 0);

        static D3D12_RESOURCE_DESC CreateBasicTextureDesc(DXGI_FORMAT format,
                                                          uint64_t width,
                                                          uint32_t height,
                                                          uint32_t sampleCount = 1,
                                                          uint64_t alignment = 0);

        static std::vector<MEMORY_ALLOCATION_EXPECT> GenerateBufferAllocations();

        bool IsSizeCacheEnabled() const;

        D3D12_MESSAGE_SEVERITY GetDefaultLogLevel() const;

        bool IsAdapterMicrosoftWARP() const;

      protected:
        ComPtr<IDXGIAdapter3> mAdapter;
        ComPtr<ID3D12Device> mDevice;
        std::unique_ptr<Caps> mCaps;
        std::string mTraceFile;
        DXGI_ADAPTER_DESC mAdapterDesc = {};
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_TESTS_D3D12TEST_H_
