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

#ifndef GPGMM_VK_CAPSVK_H_
#define GPGMM_VK_CAPSVK_H_

#include "gpgmm/vk/VKPlatform.h"

#include <cstdint>

namespace gpgmm::vk {

    struct VulkanFunctions;

    class Caps {
      public:
        static VkResult CreateCaps(VkPhysicalDevice physicalDevice,
                                   const VulkanFunctions& vulkanFunctions,
                                   uint32_t vulkanApiVersion,
                                   Caps** capsOut);

        uint64_t GetMaxDeviceAllocationCount() const;
        uint32_t GetVulkanApiVersion() const;

      private:
        Caps(uint32_t vulkanApiVersion);

        uint64_t mMaxDeviceAllocationCount = 0;
        uint32_t mVulkanApiVersion = 0;
    };

}  // namespace gpgmm::vk

#endif  // GPGMM_VK_CAPSVK_H_
