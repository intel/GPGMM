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

#ifndef SRC_GPGMM_VK_RESOURCEALLOCATORVK_H_
#define SRC_GPGMM_VK_RESOURCEALLOCATORVK_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/vk/FunctionsVk.h"

#include <gpgmm_vk.h>

#include <vector>

namespace gpgmm::vk {

    struct GpResourceAllocation_T final : public MemoryAllocationBase {
        GpResourceAllocation_T(const MemoryAllocationBase& allocation);
    };

    class Caps;

    struct GpResourceAllocator_T final : public ObjectBase {
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

        ScopedRef<MemoryAllocatorBase> CreateDeviceMemoryAllocator(
            const GpAllocatorCreateInfo& info,
            uint64_t memoryTypeIndex,
            uint64_t memoryAlignment);

        ScopedRef<MemoryAllocatorBase> CreateResourceSubAllocator(const GpAllocatorCreateInfo& info,
                                                                  uint64_t memoryTypeIndex,
                                                                  uint64_t memoryAlignment);

        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(GpResourceAllocator_T)

        VkDevice mDevice;
        VulkanFunctions mVulkanFunctions;
        std::unique_ptr<Caps> mCaps;

        std::vector<ScopedRef<MemoryAllocatorBase>> mResourceAllocatorsPerType;
        std::vector<ScopedRef<MemoryAllocatorBase>> mDeviceAllocatorsPerType;
        std::vector<VkMemoryType> mMemoryTypes;
    };

}  // namespace gpgmm::vk

#endif  // SRC_GPGMM_VK_RESOURCEALLOCATORVK_H_
