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

#ifndef SRC_GPGMM_D3D12_RESOURCESIZE_H_
#define SRC_GPGMM_D3D12_RESOURCESIZE_H_

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/d3d12/D3D12Platform.h"
#include "gpgmm/utils/Utils.h"

namespace gpgmm::d3d12 {

    // Generates array of resource sizes aligned per resource type.
    class ResourceSize : public gpgmm::MemorySizeClass {
      public:
        static constexpr auto GenerateAllClassSizes() {
            auto tmp0 = gpgmm::MemorySizeClass::GenerateAllClassSizes();
            auto tmp1 = ConstexprConcat<SizeClassInfo>(tmp0, kSmallResourceSizes);
            auto tmp2 = ConstexprConcat<SizeClassInfo>(tmp1, kDefaultResourceCacheSizes);
            auto tmp3 = ConstexprConcat<SizeClassInfo>(tmp2, kMSAAResourceCacheSizes);
            return tmp3;
        }

      private:
        // Small textures but non-MSAA (from 4KB to 64KB).
        static constexpr auto kSmallResourceSizes =
            GenerateAlignedSizes<16, D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT>();

        // Buffer or textures and also MSAA (from 64KB to 1MB).
        static constexpr auto kDefaultResourceCacheSizes =
            GenerateAlignedSizes<16, D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT>();

        // MSAA only textures (from 4MB to 64MB).
        static constexpr auto kMSAAResourceCacheSizes =
            GenerateAlignedSizes<16, D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT>();
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_RESOURCESIZE_H_
