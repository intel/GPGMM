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

#include "gpgmm/vk/ResourceAllocatorVk.h"

#include "gpgmm/common/BuddyMemoryAllocator.h"
#include "gpgmm/common/Defaults.h"
#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/Object.h"
#include "gpgmm/common/PooledMemoryAllocator.h"
#include "gpgmm/common/SegmentedMemoryAllocator.h"
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/SlabMemoryAllocator.h"
#include "gpgmm/vk/BackendVk.h"
#include "gpgmm/vk/CapsVk.h"
#include "gpgmm/vk/DeviceMemoryAllocatorVk.h"
#include "gpgmm/vk/DeviceMemoryVk.h"
#include "gpgmm/vk/ErrorVk.h"

namespace gpgmm::vk {

    VkResult gpCreateResourceAllocator(const GpAllocatorCreateInfo& info,
                                       GpResourceAllocator* allocatorOut) {
        return GpResourceAllocator_T::CreateResourceAllocator(info, allocatorOut);
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
        GPGMM_RETURN_IF_FAILED(
            allocator->GetFunctions().CreateBuffer(allocator->GetDevice(), pBufferCreateInfo,
                                                   /*allocationCallbacks*/ nullptr, &buffer));

        VkMemoryRequirements requirements = {};
        allocator->GetBufferMemoryRequirements(buffer, &requirements);
        if (requirements.size == 0) {
            return VK_INCOMPLETE;
        }

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
            allocator->GetDevice(), buffer,
            static_cast<DeviceMemory*>(allocation->GetMemory())->GetDeviceMemory(),
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

    VkResult gpCreateImage(GpResourceAllocator allocator,
                           const VkImageCreateInfo* pImageCreateInfo,
                           VkImage* imageOut,
                           const GpResourceAllocationCreateInfo* pAllocationCreateInfo,
                           GpResourceAllocation* allocationOut) {
        *allocationOut = VK_NULL_HANDLE;
        *imageOut = VK_NULL_HANDLE;

        if (allocator == VK_NULL_HANDLE) {
            return VK_INCOMPLETE;
        }

        // Create the image.
        VkImage image = VK_NULL_HANDLE;
        GPGMM_RETURN_IF_FAILED(
            allocator->GetFunctions().CreateImage(allocator->GetDevice(), pImageCreateInfo,
                                                  /*allocationCallbacks*/ nullptr, &image));

        VkMemoryRequirements requirements = {};
        allocator->GetImageMemoryRequirements(image, &requirements);
        if (requirements.size == 0) {
            return VK_INCOMPLETE;
        }

        // Create memory for the image.
        GpResourceAllocation allocation = VK_NULL_HANDLE;
        VkResult result =
            allocator->TryAllocateMemory(requirements, *pAllocationCreateInfo, &allocation);
        if (result != VK_SUCCESS) {
            allocator->GetFunctions().DestroyImage(allocator->GetDevice(), image,
                                                   /*allocationCallbacks*/ nullptr);
            return result;
        }

        // Associate memory with the buffer.
        result = allocator->GetFunctions().BindImageMemory(
            allocator->GetDevice(), image,
            static_cast<DeviceMemory*>(allocation->GetMemory())->GetDeviceMemory(),
            allocation->GetOffset());
        if (result != VK_SUCCESS) {
            allocator->GetFunctions().DestroyImage(allocator->GetDevice(), image,
                                                   /*allocationCallbacks*/ nullptr);
            allocator->DeallocateMemory(allocation);
            return result;
        }

        *allocationOut = allocation;
        *imageOut = image;

        return VK_SUCCESS;
    }

    void gpDestroyImage(GpResourceAllocator allocator,
                        VkImage image,
                        GpResourceAllocation allocation) {
        if (allocator == VK_NULL_HANDLE || image == VK_NULL_HANDLE) {
            return;
        }

        allocator->GetFunctions().DestroyImage(allocator->GetDevice(), image,
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
    VkResult GpResourceAllocator_T::CreateResourceAllocator(const GpAllocatorCreateInfo& info,
                                                            GpResourceAllocator* allocatorOut) {
        VulkanFunctions vkFunctions = {};
        {
            VulkanExtensions vkExtensionsRequired = {};
            vkExtensionsRequired.enableMemoryBudgetEXT =
                (info.flags & GP_ALLOCATOR_CREATE_ALWAYS_IN_BUDGET);

            if (info.pVulkanFunctions != nullptr) {
                vkFunctions.ImportFunctions(info.pVulkanFunctions);
            } else {
#if defined(GPGMM_STATIC_VULKAN_FUNCTIONS)
                vkFunctions.ImportFunctions(info.vulkanApiVersion);
#else  // GPGMM_DYNAMIC_VULKAN_FUNCTIONS
                vkFunctions.LoadInstanceFunctions(info.instance, vkExtensionsRequired,
                                                  info.vulkanApiVersion);
                vkFunctions.LoadDeviceFunctions(info.device);
#endif
            }

#ifndef NDEBUG
            AssertVulkanFunctionsExist(vkFunctions, vkExtensionsRequired, info.vulkanApiVersion);
#endif
        }

        std::unique_ptr<Caps> caps;
        {
            Caps* ptr = nullptr;
            GPGMM_RETURN_IF_FAILED(
                Caps::CreateCaps(info.physicalDevice, vkFunctions, info.vulkanApiVersion, &ptr));
            caps.reset(ptr);
        }

        GpAllocatorCreateInfo newInfo = info;
        newInfo.memoryGrowthFactor = (newInfo.memoryGrowthFactor >= 1.0)
                                         ? newInfo.memoryGrowthFactor
                                         : kDefaultMemoryGrowthFactor;

        newInfo.memoryFragmentationLimit = (newInfo.memoryFragmentationLimit > 0)
                                               ? newInfo.memoryFragmentationLimit
                                               : kDefaultMemoryFragmentationLimit;

        // By default, slab-allocate from a sorted segmented list.
        if (newInfo.poolAlgorithm == GP_ALLOCATOR_ALGORITHM_DEFAULT) {
            newInfo.poolAlgorithm = GP_ALLOCATOR_ALGORITHM_SEGMENTED_POOL;
        }

        if (newInfo.subAllocationAlgorithm == GP_ALLOCATOR_ALGORITHM_DEFAULT) {
            newInfo.subAllocationAlgorithm = GP_ALLOCATOR_ALGORITHM_SLAB;
        }

        if (allocatorOut != VK_NULL_HANDLE) {
            *allocatorOut = new GpResourceAllocator_T(newInfo, vkFunctions, std::move(caps));
        }

        return VK_SUCCESS;
    }

    GpResourceAllocator_T::GpResourceAllocator_T(const GpAllocatorCreateInfo& info,
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
                mDeviceAllocatorsPerType.emplace_back(
                    CreateDeviceMemoryAllocator(info, memoryTypeIndex, kNoRequiredAlignment));

                mResourceAllocatorsPerType.emplace_back(
                    CreateResourceSubAllocator(info, memoryTypeIndex, kNoRequiredAlignment));
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

    void GpResourceAllocator_T::GetImageMemoryRequirements(VkImage image,
                                                           VkMemoryRequirements* requirementsOut) {
        mVulkanFunctions.GetImageMemoryRequirements(mDevice, image, requirementsOut);
    }

    VkResult GpResourceAllocator_T::TryAllocateMemory(const VkMemoryRequirements& requirements,
                                                      const GpResourceAllocationCreateInfo& info,
                                                      GpResourceAllocation* allocationOut) {
        uint32_t memoryTypeIndex;
        GPGMM_RETURN_IF_FAILED(
            FindMemoryTypeIndex(requirements.memoryTypeBits, info, &memoryTypeIndex));

        const bool neverSubAllocate = info.flags & GP_ALLOCATION_CREATE_NEVER_SUBALLOCATE_MEMORY;

        MemoryAllocationRequest request = {};
        request.SizeInBytes = requirements.size;
        request.Alignment = requirements.alignment;
        request.NeverAllocate = (info.flags & GP_ALLOCATION_CREATE_NEVER_ALLOCATE_MEMORY);
        request.AlwaysCacheSize = false;
        request.AlwaysPrefetch = (info.flags & GP_ALLOCATION_CREATE_ALWAYS_PREFETCH_MEMORY);
        request.AvailableForAllocation = kInvalidSize;

        // Attempt to allocate using the most effective allocator.
        MemoryAllocator* allocator = nullptr;

        ResultOrError<std::unique_ptr<MemoryAllocation>> result;
        if (!neverSubAllocate) {
            allocator = mResourceAllocatorsPerType[memoryTypeIndex].get();
            result = allocator->TryAllocateMemory(request);
        }

        if (!result.IsSuccess()) {
            allocator = mDeviceAllocatorsPerType[memoryTypeIndex].get();
            result = allocator->TryAllocateMemory(request);
        }

        if (!result.IsSuccess()) {
            ErrorEvent(MessageId::kAllocatorFailed, true)
                << "Unable to allocate memory for resource.";
            return VK_ERROR_UNKNOWN;
        }

        *allocationOut = new GpResourceAllocation_T(*result.AcquireResult());

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

    std::unique_ptr<MemoryAllocator> GpResourceAllocator_T::CreateDeviceMemoryAllocator(
        const GpAllocatorCreateInfo& info,
        uint64_t memoryTypeIndex,
        uint64_t memoryAlignment) {
        std::unique_ptr<MemoryAllocator> deviceMemoryAllocator =
            std::make_unique<DeviceMemoryAllocator>(this, memoryTypeIndex);

        if (!(info.flags & GP_ALLOCATOR_CREATE_ALWAYS_ON_DEMAND)) {
            switch (info.poolAlgorithm) {
                case GP_ALLOCATOR_ALGORITHM_FIXED_POOL: {
                    return std::make_unique<PooledMemoryAllocator>(
                        info.preferredDeviceMemorySize, memoryAlignment,
                        std::move(deviceMemoryAllocator));
                }
                case GP_ALLOCATOR_ALGORITHM_SEGMENTED_POOL: {
                    return std::make_unique<SegmentedMemoryAllocator>(
                        std::move(deviceMemoryAllocator), memoryAlignment);
                }
                default: {
                    UNREACHABLE();
                    return {};
                }
            }
        }

        return deviceMemoryAllocator;
    }

    std::unique_ptr<MemoryAllocator> GpResourceAllocator_T::CreateResourceSubAllocator(
        const GpAllocatorCreateInfo& info,
        uint64_t memoryTypeIndex,
        uint64_t memoryAlignment) {
        std::unique_ptr<MemoryAllocator> pooledOrNonPooledAllocator =
            CreateDeviceMemoryAllocator(info, memoryTypeIndex, memoryAlignment);

        // TODO: Figure out how to specify this using Vulkan API.
        static constexpr uint64_t kMaxDeviceMemorySize = GPGMM_GB_TO_BYTES(32);

        const uint64_t memoryGrowthFactor =
            (info.memoryGrowthFactor >= 1.0) ? info.memoryGrowthFactor : kDefaultMemoryGrowthFactor;

        switch (info.subAllocationAlgorithm) {
            case GP_ALLOCATOR_ALGORITHM_BUDDY_SYSTEM: {
                return std::make_unique<BuddyMemoryAllocator>(
                    /*systemSize*/ kMaxDeviceMemorySize,
                    /*memorySize*/ std::max(memoryAlignment, info.preferredDeviceMemorySize),
                    /*memoryAlignment*/ memoryAlignment,
                    /*memoryAllocator*/ std::move(pooledOrNonPooledAllocator));
            }
            case GP_ALLOCATOR_ALGORITHM_SLAB: {
                return std::make_unique<SlabCacheAllocator>(
                    /*maxSlabSize*/ kMaxDeviceMemorySize,
                    /*minSlabSize*/ std::max(memoryAlignment, info.preferredDeviceMemorySize),
                    /*slabAlignment*/ memoryAlignment,
                    /*slabFragmentationLimit*/ info.memoryFragmentationLimit,
                    /*allowSlabPrefetch*/
                    !(info.flags & GP_ALLOCATOR_CREATE_DISABLE_MEMORY_PREFETCH),
                    /*slabGrowthFactor*/ memoryGrowthFactor,
                    /*memoryAllocator*/ std::move(pooledOrNonPooledAllocator));
            }
            default: {
                UNREACHABLE();
                return {};
            }
        }
    }

}  // namespace gpgmm::vk
