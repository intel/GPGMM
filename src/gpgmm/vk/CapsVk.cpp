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

#include "gpgmm/vk/CapsVk.h"
#include "gpgmm/vk/FunctionsVk.h"

#include <cstdint>
#include <memory>

namespace gpgmm { namespace vk {

    // static
    VkResult Caps::CreateCaps(VkPhysicalDevice physicalDevice,
                              const VulkanFunctions& vulkanFunctions,
                              uint32_t vulkanApiVersion,
                              Caps** capsOut) {
        Caps* caps = new Caps(vulkanApiVersion);

        VkPhysicalDeviceProperties deviceProperties;
        vulkanFunctions.GetPhysicalDeviceProperties(physicalDevice, &deviceProperties);

        caps->mMaxDeviceAllocationCount = deviceProperties.limits.maxMemoryAllocationCount;

        *capsOut = caps;

        return VK_SUCCESS;
    }

    Caps::Caps(uint32_t vulkanApiVersion)
        : mVulkanApiVersion(vulkanApiVersion != 0 ? vulkanApiVersion : VK_API_VERSION_1_0) {
    }

    uint64_t Caps::GetMaxDeviceAllocationCount() const {
        return mMaxDeviceAllocationCount;
    }

    uint32_t Caps::GetVulkanApiVersion() const {
        return mVulkanApiVersion;
    }

}}  // namespace gpgmm::vk
