// Copyright 2019 The Dawn Authors
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

#include "gpgmm/vk/DeviceMemoryAllocatorVk.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/vk/BackendVk.h"
#include "gpgmm/vk/CapsVk.h"
#include "gpgmm/vk/DeviceMemoryVk.h"
#include "gpgmm/vk/ResourceAllocatorVk.h"

namespace gpgmm::vk {

    DeviceMemoryAllocator::DeviceMemoryAllocator(GpResourceAllocator resourceAllocator,
                                                 uint32_t memoryTypeIndex)
        : mResourceAllocator(resourceAllocator), mMemoryTypeIndex(memoryTypeIndex) {
    }

    std::unique_ptr<MemoryAllocation> DeviceMemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "DeviceMemoryAllocator.TryAllocateMemory");

        if (request.NeverAllocate) {
            return {};
        }

        const uint64_t maxDeviceMemoryAllocationCount =
            mResourceAllocator->GetCaps()->GetMaxDeviceAllocationCount();
        if (mInfo.UsedMemoryCount + 1 >= maxDeviceMemoryAllocationCount) {
            DebugEvent("DeviceMemoryAllocator.TryAllocateMemory", EventMessageId::AllocatorFailed)
                << "Device exceeded max number of device memory allocations (" +
                       std::to_string(mInfo.UsedMemoryCount) + " vs " +
                       std::to_string(maxDeviceMemoryAllocationCount) + ").";
            return {};
        }

        GPGMM_INVALID_IF(!ValidateRequest(request));

        VkMemoryAllocateInfo allocateInfo = {};
        allocateInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        allocateInfo.pNext = nullptr;
        allocateInfo.allocationSize = request.SizeInBytes;
        allocateInfo.memoryTypeIndex = mMemoryTypeIndex;

        VkDeviceMemory deviceMemory = VK_NULL_HANDLE;
        if (mResourceAllocator->GetFunctions().AllocateMemory(mResourceAllocator->GetDevice(),
                                                              &allocateInfo, nullptr,
                                                              &deviceMemory) != VK_SUCCESS) {
            return {};
        }

        mInfo.UsedMemoryUsage += request.SizeInBytes;
        mInfo.UsedMemoryCount++;

        return std::make_unique<MemoryAllocation>(
            this,
            new DeviceMemory(deviceMemory, mMemoryTypeIndex, request.SizeInBytes,
                             request.Alignment),
            request.SizeInBytes);
    }

    void DeviceMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "DeviceMemoryAllocator.DeallocateMemory");

        VkDeviceMemory deviceMemory = ToBackend(allocation->GetMemory())->GetDeviceMemory();
        mResourceAllocator->GetFunctions().FreeMemory(mResourceAllocator->GetDevice(), deviceMemory,
                                                      /*allocationCallbacks*/ nullptr);

        mInfo.UsedMemoryUsage -= allocation->GetSize();
        mInfo.UsedMemoryCount--;

        SafeRelease(allocation);
    }
}  // namespace gpgmm::vk
