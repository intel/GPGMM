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

#include "tests/VKTest.h"

#include <gpgmm_vk.h>

#include <vector>

namespace gpgmm::vk {

    void VKTestBase::SetUp() {
        GPGMMTestBase::SetUp();

        // Setup the instance.

        // TODO
        std::vector<const char*> enabledExtensions = {};
        std::vector<const char*> instanceLayers = {};

        VkApplicationInfo appInfo = {};
        appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
        appInfo.pNext = nullptr;
        appInfo.pApplicationName = "End2End Tests";
        appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
        appInfo.pEngineName = "GPGMM";
        appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
        appInfo.apiVersion = VK_API_VERSION_1_0;

        VkInstanceCreateInfo instanceInfo = {};
        instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        instanceInfo.pNext = nullptr;
        instanceInfo.pApplicationInfo = &appInfo;
        instanceInfo.enabledExtensionCount = static_cast<uint32_t>(enabledExtensions.size());
        instanceInfo.ppEnabledExtensionNames = enabledExtensions.data();
        instanceInfo.enabledLayerCount = static_cast<uint32_t>(instanceLayers.size());
        instanceInfo.ppEnabledLayerNames = instanceLayers.data();

        // vkCreateInstance fails if no Vulkan ICD was installed.
        // TODO: Consider installing a fall-back CPU-based Vulkan driver for testing.
        GPGMM_SKIP_TEST_IF_UNSUPPORTED(vkCreateInstance(&instanceInfo, nullptr, &mInstance) !=
                                       VK_SUCCESS);

        // Setup the physical device
        {
            uint32_t physicalDeviceCount = 0;
            ASSERT_SUCCESS(vkEnumeratePhysicalDevices(mInstance, &physicalDeviceCount, nullptr));
            ASSERT_GT(physicalDeviceCount, 0u);

            std::vector<VkPhysicalDevice> physicalDevices(physicalDeviceCount);
            ASSERT_SUCCESS(vkEnumeratePhysicalDevices(mInstance, &physicalDeviceCount,
                                                      physicalDevices.data()));

            mPhysicalDevice = physicalDevices[0];
        }

        ASSERT_FALSE(mPhysicalDevice == VK_NULL_HANDLE);

        // Setup a single (universal) queue.
        uint32_t queueFamilyIndex = 0;
        {
            uint32_t queueFamilyCount = 0;
            vkGetPhysicalDeviceQueueFamilyProperties(mPhysicalDevice, &queueFamilyCount, nullptr);

            std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
            vkGetPhysicalDeviceQueueFamilyProperties(mPhysicalDevice, &queueFamilyCount,
                                                     queueFamilies.data());

            // Note that GRAPHICS and COMPUTE imply TRANSFER so we don't need to check for it.
            constexpr uint32_t kUniversalFlags = VK_QUEUE_GRAPHICS_BIT | VK_QUEUE_COMPUTE_BIT;
            int universalQueueFamily = -1;
            for (unsigned int i = 0; i < queueFamilyCount; ++i) {
                if ((queueFamilies[i].queueFlags & kUniversalFlags) == kUniversalFlags) {
                    universalQueueFamily = i;
                    break;
                }
            }
            ASSERT_NE(universalQueueFamily, -1);
            queueFamilyIndex = static_cast<uint32_t>(universalQueueFamily);
        }

        std::vector<VkDeviceQueueCreateInfo> queueCreateInfo = {};
        {
            VkDeviceQueueCreateInfo queueInfo = {};
            queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
            queueInfo.pNext = nullptr;
            queueInfo.flags = 0;
            queueInfo.queueFamilyIndex = static_cast<uint32_t>(queueFamilyIndex);
            queueInfo.queueCount = 1;
            float zero = 0.0f;
            queueInfo.pQueuePriorities = &zero;
            queueCreateInfo.push_back(queueInfo);
        }

        // Setup the device

        VkDeviceCreateInfo deviceInfo = {};
        deviceInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        deviceInfo.pNext = nullptr;
        deviceInfo.flags = 0;
        deviceInfo.enabledLayerCount = 0;
        deviceInfo.ppEnabledLayerNames = nullptr;
        deviceInfo.enabledExtensionCount = static_cast<uint32_t>(enabledExtensions.size());
        deviceInfo.ppEnabledExtensionNames =
            !enabledExtensions.empty() ? enabledExtensions.data() : nullptr;
        deviceInfo.queueCreateInfoCount = static_cast<uint32_t>(queueCreateInfo.size());
        deviceInfo.pQueueCreateInfos = queueCreateInfo.data();

        ASSERT_SUCCESS(vkCreateDevice(mPhysicalDevice, &deviceInfo, nullptr, &mDevice));
    }

    void VKTestBase::TearDown() {
        GPGMMTestBase::TearDown();

        if (mDevice != VK_NULL_HANDLE) {
            vkDestroyDevice(mDevice, nullptr);
        }

        if (mInstance != VK_NULL_HANDLE) {
            vkDestroyInstance(mInstance, nullptr);
        }
    }

    GpAllocatorCreateInfo VKTestBase::CreateBasicAllocatorInfo() const {
        GpAllocatorCreateInfo allocatorInfo = {};
        allocatorInfo.device = mDevice;
        allocatorInfo.instance = mInstance;
        allocatorInfo.physicalDevice = mPhysicalDevice;
        return allocatorInfo;
    }

}  // namespace gpgmm::vk
