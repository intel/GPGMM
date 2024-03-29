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

#ifndef SRC_GPGMM_VK_DEVICEMEMORYALLOCATORVK_H_
#define SRC_GPGMM_VK_DEVICEMEMORYALLOCATORVK_H_

#include "gpgmm/vk/ResourceAllocatorVk.h"

namespace gpgmm::vk {
    class DeviceMemoryAllocator final : public MemoryAllocatorBase {
      public:
        DeviceMemoryAllocator(GpResourceAllocator resourceAllocator, uint32_t memoryTypeIndex);
        ~DeviceMemoryAllocator() override = default;

        // MemoryAllocatorBase interface
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) override;

      private:
        GpResourceAllocator mResourceAllocator;
        uint32_t mMemoryTypeIndex;
    };

}  // namespace gpgmm::vk

#endif  // SRC_GPGMM_VK_DEVICEMEMORYALLOCATORVK_H_
