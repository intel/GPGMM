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

#include "gpgmm/vk/vk_platform.h"

namespace gpgmm::vk {

    // Vulkan entrypoints used by GPGMM.
    struct VulkanFunctions {
        // Used to dynamically set functions from a shared library (DLL or so).
        void LoadInstanceFunctions(VkInstance instance);
        void LoadDeviceFunctions(VkDevice device);

        // Used to statically set functions from a static library (Vulkan loader).
        void ImportDeviceFunctions();

        // Used to import pre-loaded functions set by the user.
        void ImportDeviceFunctions(const VulkanFunctions* vkFunctions);

        // Order is important: instance must be loaded before device.
        PFN_vkGetInstanceProcAddr GetInstanceProcAddr = nullptr;

        // Core Vulkan 1.0
        PFN_vkGetDeviceProcAddr GetDeviceProcAddr = nullptr;
        PFN_vkGetPhysicalDeviceProperties GetPhysicalDeviceProperties = nullptr;
        PFN_vkGetPhysicalDeviceMemoryProperties GetPhysicalDeviceMemoryProperties = nullptr;
        PFN_vkAllocateMemory AllocateMemory = nullptr;
        PFN_vkBindBufferMemory BindBufferMemory = nullptr;
        PFN_vkFreeMemory FreeMemory = nullptr;
        PFN_vkMapMemory MapMemory = nullptr;
        PFN_vkGetBufferMemoryRequirements GetBufferMemoryRequirements = nullptr;
        PFN_vkGetImageMemoryRequirements GetImageMemoryRequirements = nullptr;
        PFN_vkCreateBuffer CreateBuffer = nullptr;
        PFN_vkDestroyBuffer DestroyBuffer = nullptr;
        PFN_vkCreateImage CreateImage = nullptr;
        PFN_vkDestroyImage DestroyImage = nullptr;
    };

    // ASSERTs if any Vulkan function is left unset.
    void AssertVulkanFunctionsExist(const VulkanFunctions& vkFunctions);

}  // namespace gpgmm::vk
