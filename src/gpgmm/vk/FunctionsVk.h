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

#include "gpgmm/vk/vk_platform.h"

namespace gpgmm::vk {

    // Used to determine which dynamically linked functions to load based on the required Vulkan API
    // extension.
    struct VulkanExtensions {
        bool enableMemoryBudgetEXT = false;
    };

    // Vulkan entrypoints used by GPGMM.
    struct VulkanFunctions {
        // Used to dynamically set functions from a shared library (DLL or so).
        void LoadInstanceFunctions(VkInstance instance,
                                   const VulkanExtensions& vkExtensions,
                                   uint32_t vkApiVersion);
        void LoadDeviceFunctions(VkDevice device);

        // Used to statically set functions from a static library (Vulkan loader).
        void ImportFunctions(uint32_t vkApiVersion);

        // Used to import pre-loaded functions set by the user.
        void ImportFunctions(const VulkanFunctions* vkFunctions);

        // Order is important: instance must be loaded before device.
        PFN_vkGetInstanceProcAddr GetInstanceProcAddr = nullptr;

        // Core Vulkan 1.0
        PFN_vkGetDeviceProcAddr GetDeviceProcAddr = nullptr;
        PFN_vkGetPhysicalDeviceProperties GetPhysicalDeviceProperties = nullptr;
        PFN_vkGetPhysicalDeviceMemoryProperties GetPhysicalDeviceMemoryProperties = nullptr;
        PFN_vkAllocateMemory AllocateMemory = nullptr;
        PFN_vkBindBufferMemory BindBufferMemory = nullptr;
        PFN_vkBindImageMemory BindImageMemory = nullptr;
        PFN_vkFreeMemory FreeMemory = nullptr;
        PFN_vkMapMemory MapMemory = nullptr;
        PFN_vkGetBufferMemoryRequirements GetBufferMemoryRequirements = nullptr;
        PFN_vkGetImageMemoryRequirements GetImageMemoryRequirements = nullptr;
        PFN_vkCreateBuffer CreateBuffer = nullptr;
        PFN_vkCreateImage CreateImage = nullptr;
        PFN_vkDestroyImage DestroyImage = nullptr;
        PFN_vkDestroyBuffer DestroyBuffer = nullptr;

        // Core Vulkan 1.1
        PFN_vkGetPhysicalDeviceMemoryProperties2 GetPhysicalDeviceMemoryProperties2 = nullptr;
    };

    // ASSERTs if any Vulkan function is left unset.
    void AssertVulkanFunctionsExist(const VulkanFunctions& vkFunctions,
                                    const VulkanExtensions& vkExtensions,
                                    uint32_t vkApiVersion);

}  // namespace gpgmm::vk
