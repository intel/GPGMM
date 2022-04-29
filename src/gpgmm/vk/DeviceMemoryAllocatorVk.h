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

#ifndef GPGMM_VK_DEVICEMEMORYALLOCATORVK_H_
#define GPGMM_VK_DEVICEMEMORYALLOCATORVK_H_

#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/vk/vk_platform.h"

namespace gpgmm { namespace vk {

    VK_DEFINE_HANDLE(GpResourceAllocator)

    class DeviceMemoryAllocator final : public MemoryAllocator {
      public:
        DeviceMemoryAllocator(GpResourceAllocator resourceAllocator,
                              uint32_t memoryTypeIndex,
                              VkDeviceSize memorySize);
        ~DeviceMemoryAllocator() override = default;

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t requestSize,
                                                            uint64_t alignment,
                                                            bool neverAllocate,
                                                            bool cacheSize,
                                                            bool prefetchMemory) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

      private:
        GpResourceAllocator mResourceAllocator;
        uint32_t mMemoryTypeIndex;
        VkDeviceSize mMemorySize;
    };

}}  // namespace gpgmm::vk

#endif  // GPGMM_VK_DEVICEMEMORYALLOCATORVK_H_
