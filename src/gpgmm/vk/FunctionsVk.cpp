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

#include "gpgmm/vk/FunctionsVk.h"

#include "gpgmm/common/Assert.h"

#define GPGMM_DYNAMIC_GET_INSTANCE_FUNC(functionName)            \
    do {                                                         \
        functionName = reinterpret_cast<decltype(functionName)>( \
            GetInstanceProcAddr(instance, "vk" #functionName));  \
    } while (0)

#define GPGMM_DYNAMIC_GET_DEVICE_FUNC(functionName)              \
    do {                                                         \
        functionName = reinterpret_cast<decltype(functionName)>( \
            GetDeviceProcAddr(device, "vk" #functionName));      \
    } while (0)

#define GPGMM_STATIC_GET_FUNC(functionName)                                        \
    do {                                                                           \
        functionName = reinterpret_cast<decltype(functionName)>(vk##functionName); \
    } while (0)

namespace gpgmm { namespace vk {
    void VulkanFunctions::LoadInstanceFunctions(VkInstance instance) {
        GPGMM_DYNAMIC_GET_INSTANCE_FUNC(GetDeviceProcAddr);
        GPGMM_DYNAMIC_GET_INSTANCE_FUNC(GetPhysicalDeviceMemoryProperties);
        GPGMM_DYNAMIC_GET_INSTANCE_FUNC(GetPhysicalDeviceProperties);
        // TODO
    }

    void VulkanFunctions::LoadDeviceFunctions(VkDevice device) {
        GPGMM_DYNAMIC_GET_DEVICE_FUNC(AllocateMemory);
        GPGMM_DYNAMIC_GET_DEVICE_FUNC(FreeMemory);
        GPGMM_DYNAMIC_GET_DEVICE_FUNC(BindBufferMemory);
        GPGMM_DYNAMIC_GET_DEVICE_FUNC(GetBufferMemoryRequirements);
        GPGMM_DYNAMIC_GET_DEVICE_FUNC(CreateBuffer);
        GPGMM_DYNAMIC_GET_DEVICE_FUNC(DestroyBuffer);
        // TODO
    }

    void VulkanFunctions::ImportDeviceFunctions() {
        GPGMM_STATIC_GET_FUNC(GetPhysicalDeviceMemoryProperties);
        GPGMM_STATIC_GET_FUNC(GetPhysicalDeviceProperties);
        GPGMM_STATIC_GET_FUNC(AllocateMemory);
        GPGMM_STATIC_GET_FUNC(FreeMemory);
        GPGMM_STATIC_GET_FUNC(BindBufferMemory);
        GPGMM_STATIC_GET_FUNC(GetBufferMemoryRequirements);
        GPGMM_STATIC_GET_FUNC(CreateBuffer);
        GPGMM_STATIC_GET_FUNC(DestroyBuffer);
        // TODO
    }

    void VulkanFunctions::ImportDeviceFunctions(const VulkanFunctions* vulkanFunctions) {
        // TODO
    }

    void VulkanFunctions::AssertVulkanFunctionsAreValid() {
        ASSERT(GetPhysicalDeviceMemoryProperties != nullptr);
        ASSERT(GetPhysicalDeviceProperties != nullptr);
        ASSERT(AllocateMemory != nullptr);
        ASSERT(FreeMemory != nullptr);
        ASSERT(BindBufferMemory != nullptr);
        ASSERT(GetBufferMemoryRequirements != nullptr);
        ASSERT(CreateBuffer != nullptr);
        ASSERT(DestroyBuffer != nullptr);
    }

}}  // namespace gpgmm::vk
