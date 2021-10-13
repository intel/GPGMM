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

#include "src/tests/GPGMMTest.h"

#include "src/d3d12/d3d12_platform.h"

namespace gpgmm { namespace d3d12 {

    struct ALLOCATOR_DESC;
    class ResourceAllocator;
    class ResourceAllocation;

    class D3D12TestBase : public GPGMMTestBase {
      public:
        void SetUp();
        void TearDown();

        ALLOCATOR_DESC CreateBasicAllocatorDesc() const;

      protected:
        ComPtr<IDXGIAdapter3> mAdapter;
        ComPtr<ID3D12Device> mDevice;

        bool mIsUMA = false;
        uint32_t mResourceHeapTier = 1;
    };

}}  // namespace gpgmm::d3d12
