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

#ifndef GPGMM_VK_RESOURCEALLOCATORVK_H_
#define GPGMM_VK_RESOURCEALLOCATORVK_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/vk/FunctionsVk.h"

#include <gpgmm_vk.h>

#include <vector>

namespace gpgmm::vk {

    struct GpResourceAllocation_T final : public MemoryAllocation {
        GpResourceAllocation_T(const MemoryAllocation& allocation);
    };

    class Caps;

    struct GpResourceAllocator_T {
      public:
        static VkResult CreateResourceAllocator(const GpAllocatorCreateInfo& info,
                                                GpResourceAllocator* allocatorOut);

        VkResult TryAllocateMemory(const VkMemoryRequirements& requirements,
                                   const GpResourceAllocationCreateInfo& allocationInfo,
                                   GpResourceAllocation* allocationOut);

        void DeallocateMemory(GpResourceAllocation allocation);

        void GetBufferMemoryRequirements(VkBuffer buffer, VkMemoryRequirements* requirementsOut);
        void GetImageMemoryRequirements(VkImage image, VkMemoryRequirements* requirementsOut);

        VkDevice GetDevice() const;
        VulkanFunctions GetFunctions() const;
        Caps* GetCaps() const;

      private:
        GpResourceAllocator_T(const GpAllocatorCreateInfo& info,
                              const VulkanFunctions& vulkanFunctions,
                              std::unique_ptr<Caps> caps);

        VkResult FindMemoryTypeIndex(uint32_t memoryTypeBits,
                                     const GpResourceAllocationCreateInfo& allocationInfo,
                                     uint32_t* memoryTypeIndexOut);

        std::unique_ptr<MemoryAllocator> CreateDeviceMemoryAllocator(
            const GpAllocatorCreateInfo& info,
            uint64_t memoryTypeIndex,
            uint64_t memoryAlignment);

        std::unique_ptr<MemoryAllocator> CreateResourceSubAllocator(
            const GpAllocatorCreateInfo& info,
            uint64_t memoryTypeIndex,
            uint64_t memoryAlignment);

        VkDevice mDevice;
        VulkanFunctions mVulkanFunctions;
        std::unique_ptr<Caps> mCaps;

        std::vector<std::unique_ptr<MemoryAllocator>> mResourceAllocatorsPerType;
        std::vector<std::unique_ptr<MemoryAllocator>> mDeviceAllocatorsPerType;
        std::vector<VkMemoryType> mMemoryTypes;
    };

}  // namespace gpgmm::vk

#endif  // GPGMM_VK_RESOURCEALLOCATORVK_H_
