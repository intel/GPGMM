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

#ifndef TESTS_D3D12TEST_H_
#define TESTS_D3D12TEST_H_

#include "tests/GPGMMTest.h"

#include <vector>

#include "gpgmm/d3d12/d3d12_platform.h"

#define ASSERT_FAILED(expr) ASSERT_TRUE(FAILED(expr))
#define ASSERT_SUCCEEDED(expr) ASSERT_TRUE(SUCCEEDED(expr))

#define EXPECT_FAILED(expr) EXPECT_TRUE(FAILED(expr))
#define EXPECT_SUCCEEDED(expr) EXPECT_TRUE(SUCCEEDED(expr))

namespace gpgmm::d3d12 {

    struct ALLOCATOR_DESC;
    class ResourceAllocator;
    class ResourceAllocation;

    D3D12_MESSAGE_SEVERITY GetMessageSeverity(LogSeverity logSeverity);

    class D3D12TestBase : public GPGMMTestBase {
      public:
        void SetUp();
        void TearDown();

        ALLOCATOR_DESC CreateBasicAllocatorDesc(bool isPrefetchAllowed = false) const;

        static D3D12_RESOURCE_DESC CreateBasicBufferDesc(uint64_t width, uint64_t alignment = 0);

        static D3D12_RESOURCE_DESC CreateBasicTextureDesc(DXGI_FORMAT format,
                                                          uint64_t width,
                                                          uint32_t height,
                                                          uint32_t sampleCount = 1,
                                                          uint64_t alignment = 0);

        static std::vector<MEMORY_ALLOCATION_EXPECT> GenerateBufferAllocations();

        bool IsSizeCacheEnabled() const;

        D3D12_MESSAGE_SEVERITY GetDefaultLogLevel() const;

      protected:
        ComPtr<IDXGIAdapter3> mAdapter;
        ComPtr<ID3D12Device> mDevice;

        bool mIsUMA = false;
        D3D12_RESOURCE_HEAP_TIER mResourceHeapTier = D3D12_RESOURCE_HEAP_TIER_1;
    };

}  // namespace gpgmm::d3d12

#endif  // TESTS_D3D12TEST_H_
