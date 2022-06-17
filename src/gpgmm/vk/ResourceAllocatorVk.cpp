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

#include "gpgmm/vk/ResourceAllocatorVk.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/vk/BackendVk.h"
#include "gpgmm/vk/CapsVk.h"
#include "gpgmm/vk/DeviceMemoryAllocatorVk.h"
#include "gpgmm/vk/DeviceMemoryVk.h"
#include "gpgmm/vk/ErrorVk.h"

namespace gpgmm::vk {

    VkResult gpCreateResourceAllocator(const GpCreateAllocatorInfo& info,
                                       GpResourceAllocator* allocatorOut) {
        return GpResourceAllocator_T::CreateAllocator(info, allocatorOut);
    }

    void gpDestroyResourceAllocator(GpResourceAllocator allocator) {
        if (allocator == VK_NULL_HANDLE) {
            return;
        }
        SafeDelete(allocator);
    }

    VkResult gpCreateBuffer(GpResourceAllocator allocator,
                            const VkBufferCreateInfo* pBufferCreateInfo,
                            VkBuffer* bufferOut,
                            const GpResourceAllocationCreateInfo* pAllocationCreateInfo,
                            GpResourceAllocation* allocationOut) {
        *allocationOut = VK_NULL_HANDLE;
        *bufferOut = VK_NULL_HANDLE;

        if (allocator == VK_NULL_HANDLE) {
            return VK_INCOMPLETE;
        }

        // Create the buffer.
        VkBuffer buffer = VK_NULL_HANDLE;
        ReturnIfFailed(
            allocator->GetFunctions().CreateBuffer(allocator->GetDevice(), pBufferCreateInfo,
                                                   /*allocationCallbacks*/ nullptr, &buffer));

        VkMemoryRequirements requirements = {};
        allocator->GetBufferMemoryRequirements(buffer, &requirements);

        // Create memory for the buffer.
        GpResourceAllocation allocation = VK_NULL_HANDLE;
        VkResult result =
            allocator->TryAllocateMemory(requirements, *pAllocationCreateInfo, &allocation);
        if (result != VK_SUCCESS) {
            allocator->GetFunctions().DestroyBuffer(allocator->GetDevice(), buffer,
                                                    /*allocationCallbacks*/ nullptr);
            return result;
        }

        // Associate memory with the buffer.
        result = allocator->GetFunctions().BindBufferMemory(
            allocator->GetDevice(), buffer, ToBackend(allocation->GetMemory())->GetDeviceMemory(),
            allocation->GetOffset());
        if (result != VK_SUCCESS) {
            allocator->GetFunctions().DestroyBuffer(allocator->GetDevice(), buffer,
                                                    /*allocationCallbacks*/ nullptr);
            allocator->DeallocateMemory(allocation);
            return result;
        }

        *allocationOut = allocation;
        *bufferOut = buffer;

        return VK_SUCCESS;
    }

    void gpDestroyBuffer(GpResourceAllocator allocator,
                         VkBuffer buffer,
                         GpResourceAllocation allocation) {
        if (allocator == VK_NULL_HANDLE || buffer == VK_NULL_HANDLE) {
            return;
        }

        allocator->GetFunctions().DestroyBuffer(allocator->GetDevice(), buffer,
                                                /*allocationCallbacks*/ nullptr);

        if (allocation == VK_NULL_HANDLE) {
            return;
        }

        allocator->DeallocateMemory(allocation);
    }

    // GpResourceAllocation_T

    GpResourceAllocation_T::GpResourceAllocation_T(const MemoryAllocation& allocation)
        : MemoryAllocation(allocation) {
    }

    // GpResourceAllocator_T

    // static
    VkResult GpResourceAllocator_T::CreateAllocator(const GpCreateAllocatorInfo& info,
                                                    GpResourceAllocator* allocatorOut) {
        VulkanFunctions vulkanFunctions = {};
        {
            if (info.pVulkanFunctions != nullptr) {
                vulkanFunctions.ImportDeviceFunctions(info.pVulkanFunctions);
            } else {
#if defined(GPGMM_STATIC_VULKAN_FUNCTIONS)
                vulkanFunctions.ImportDeviceFunctions();
#else  // GPGMM_DYNAMIC_VULKAN_FUNCTIONS
                vulkanFunctions.LoadInstanceFunctions(info.instance);
                vulkanFunctions.LoadDeviceFunctions(info.device);
#endif
            }

#ifndef NDEBUG
            vulkanFunctions.AssertVulkanFunctionsAreValid();
#endif
        }

        std::unique_ptr<Caps> caps;
        {
            Caps* ptr = nullptr;
            ReturnIfFailed(Caps::CreateCaps(info.physicalDevice, vulkanFunctions,
                                            info.vulkanApiVersion, &ptr));
            caps.reset(ptr);
        }

        if (allocatorOut != VK_NULL_HANDLE) {
            *allocatorOut = new GpResourceAllocator_T(info, vulkanFunctions, std::move(caps));
        }

        return VK_SUCCESS;
    }

    GpResourceAllocator_T::GpResourceAllocator_T(const GpCreateAllocatorInfo& info,
                                                 const VulkanFunctions& vulkanFunctions,
                                                 std::unique_ptr<Caps> caps)
        : mDevice(info.device), mVulkanFunctions(vulkanFunctions), mCaps(std::move(caps)) {
        VkPhysicalDeviceMemoryProperties memoryProperties = {};
        mVulkanFunctions.GetPhysicalDeviceMemoryProperties(info.physicalDevice, &memoryProperties);
        {
            mMemoryTypes.assign(memoryProperties.memoryTypes,
                                memoryProperties.memoryTypes + memoryProperties.memoryTypeCount);

            std::vector<VkMemoryHeap> memoryHeaps;
            memoryHeaps.assign(memoryProperties.memoryHeaps,
                               memoryProperties.memoryHeaps + memoryProperties.memoryHeapCount);

            for (uint32_t memoryTypeIndex = 0; memoryTypeIndex < mMemoryTypes.size();
                 memoryTypeIndex++) {
                mDeviceAllocatorsPerType.emplace_back(std::make_unique<DeviceMemoryAllocator>(
                    this, memoryTypeIndex,
                    memoryHeaps[mMemoryTypes[memoryTypeIndex].heapIndex].size));
            }
        }
    }

    VkResult GpResourceAllocator_T::FindMemoryTypeIndex(
        uint32_t memoryTypeBits,
        const GpResourceAllocationCreateInfo& allocationInfo,
        uint32_t* memoryTypeIndexOut) {
        *memoryTypeIndexOut = UINT32_MAX;

        const VkFlags& requiredPropertyFlags = allocationInfo.requiredPropertyFlags;

        uint32_t bestMemoryTypeIndex = UINT32_MAX;
        for (uint32_t memoryTypeIndex = 0; memoryTypeIndex < mMemoryTypes.size();
             ++memoryTypeIndex) {
            const VkMemoryPropertyFlags& currPropertyFlags =
                mMemoryTypes[memoryTypeIndex].propertyFlags;

            // Memory type must be acceptable for this memoryTypeBits.
            if ((memoryTypeBits & (1 << memoryTypeIndex)) == 0) {
                continue;
            }

            // Memory type must have all the required property flags.
            if ((currPropertyFlags & requiredPropertyFlags) != requiredPropertyFlags) {
                continue;
            }

            // Found the first candidate memory type
            if (*memoryTypeIndexOut == UINT32_MAX) {
                bestMemoryTypeIndex = memoryTypeIndex;
                continue;
            }
        }

        if (bestMemoryTypeIndex == UINT32_MAX) {
            return VK_ERROR_FEATURE_NOT_PRESENT;
        }

        *memoryTypeIndexOut = bestMemoryTypeIndex;

        return VK_SUCCESS;
    }

    void GpResourceAllocator_T::GetBufferMemoryRequirements(VkBuffer buffer,
                                                            VkMemoryRequirements* requirementsOut) {
        mVulkanFunctions.GetBufferMemoryRequirements(mDevice, buffer, requirementsOut);
    }

    VkResult GpResourceAllocator_T::TryAllocateMemory(
        const VkMemoryRequirements& requirements,
        const GpResourceAllocationCreateInfo& allocationInfo,
        GpResourceAllocation* allocationOut) {
        uint32_t memoryTypeIndex;
        ReturnIfFailed(
            FindMemoryTypeIndex(requirements.memoryTypeBits, allocationInfo, &memoryTypeIndex));

        MemoryAllocator* allocator = mDeviceAllocatorsPerType[memoryTypeIndex].get();

        MemoryAllocationRequest request = {};
        request.SizeInBytes = requirements.size;
        request.Alignment = requirements.alignment;
        request.NeverAllocate = (allocationInfo.flags & GP_ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY);
        request.AlwaysCacheSize = false;
        request.AlwaysPrefetch = (allocationInfo.flags & GP_ALLOCATION_FLAG_ALWAYS_PREFETCH_MEMORY);

        std::unique_ptr<MemoryAllocation> memoryAllocation = allocator->TryAllocateMemory(request);
        if (memoryAllocation == nullptr) {
            InfoEvent("GpResourceAllocator.TryAllocateResource", EventMessageId::AllocatorFailed)
                << std::string(allocator->GetTypename()) +
                       " failed to allocate memory for resource.";

            return VK_ERROR_UNKNOWN;
        }

        *allocationOut = new GpResourceAllocation_T(*memoryAllocation);

        return VK_SUCCESS;
    }

    void GpResourceAllocator_T::DeallocateMemory(GpResourceAllocation allocation) {
        if (allocation == VK_NULL_HANDLE) {
            return;
        }
        allocation->GetAllocator()->DeallocateMemory(std::unique_ptr<MemoryAllocation>(allocation));
    }

    VkDevice GpResourceAllocator_T::GetDevice() const {
        return mDevice;
    }

    VulkanFunctions GpResourceAllocator_T::GetFunctions() const {
        return mVulkanFunctions;
    }

    Caps* GpResourceAllocator_T::GetCaps() const {
        return mCaps.get();
    }
}  // namespace gpgmm::vk
