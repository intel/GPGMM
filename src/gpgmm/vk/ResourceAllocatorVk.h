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

#ifndef GPGMM_VK_RESOURCEALLOCATORVK_H_
#define GPGMM_VK_RESOURCEALLOCATORVK_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/utils/Flags.h"
#include "gpgmm/vk/FunctionsVk.h"
#include "include/gpgmm_export.h"

#include <vector>

namespace gpgmm {
    class MemoryAllocation;
}  // namespace gpgmm

namespace gpgmm { namespace vk {

    /** \struct GpResourceAllocator
    \brief Opaque handle to a allocator object.
    */
    VK_DEFINE_HANDLE(GpResourceAllocator)

    /** \struct GpResourceAllocation
    \breif Opaque handle to a resource allocation object.
    */
    VK_DEFINE_HANDLE(GpResourceAllocation)

    /** \struct GpCreateAllocatorInfo
    Specifies how allocators should be created.
    */
    struct GpCreateAllocatorInfo {
        /** \brief Function pointer to Vulkan functions.
         */
        const VulkanFunctions* pVulkanFunctions = nullptr;

        /** \brief Handle to Vulkan physical device object.
         */
        VkPhysicalDevice physicalDevice;

        /** \brief Handle to Vulkan device object.
         */
        VkDevice device;

        /** \brief Handle to Vulkan instance object.
         */
        VkInstance instance;

        /** \brief Vulkan version return by VK_MAKE_VERSION.
         */
        uint32_t vulkanApiVersion;
    };

    enum GpResourceAllocationCreateFlags {

        /** \brief Disables all allocation flags.

        Enabled by default.
        */
        GP_ALLOCATION_FLAG_NONE = 0x0,

        /** \brief  Disallow creating new device memory when creating a resource.

        Forbids creating new device memory when creating a resource. The created resource
        must use existing device memory or error. Effectively disables creating
        standalone allocations whose memory cannot be reused.
        */
        GP_ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY = 0x1,

        /** \brief Disallow creating multiple resource allocations from the same device memory.

        The created resource will always be allocated with it's own device memory.
        */
        GP_ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY = 0x4,

        /** \brief Prefetch memory for the next resource allocation.

        The call to prefetch is deferred to a seperate background thread by GPGMM which runs
        when the current allocation requested is completed. By default, GPGMM will automatically
        trigger prefetching based on heurstics. Prefetching enables more performance when
        allocating for large contiguous allocations. Should not be used with
        ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY.
        */
        GP_ALLOCATION_FLAG_ALWAYS_PREFETCH_MEMORY = 0x8,
    };

    /** \struct GpResourceAllocationCreateInfo
    Specifies how allocations should be created.
    */
    struct GpResourceAllocationCreateInfo {
        /** \brief Flags used to control how the resource will be allocated.
         */
        GpResourceAllocationCreateFlags flags;

        /** \brief Bitmask to specify required memory properties for the allocation.
         */
        VkMemoryPropertyFlags requiredPropertyFlags;
    };

    /** \brief  Create allocator used to create and manage video memory for the App specified device
    and instance.

    @param info A reference to GpCreateAllocatorInfo structure that describes the allocator.
    @param[out] allocatorOut Pointer to a memory block that recieves a pointer to the
    resource allocator. Pass NULL to test if allocator creation would succeed, but not actually
    create the allocator. If NULL is passed and allocator creating would succeed, VK_INCOMPLETE is
    returned.
    */
    GPGMM_EXPORT VkResult gpCreateResourceAllocator(const GpCreateAllocatorInfo& info,
                                                    GpResourceAllocator* allocatorOut);

    /** \brief  Destroy allocator.

    @param allocator A GpResourceAllocator to destroy.
    */
    GPGMM_EXPORT void gpDestroyResourceAllocator(GpResourceAllocator allocator);

    /** \brief  Create a buffer allocation.

    @param allocator A GpResourceAllocator used to create the buffer and allocation.
    @param pBufferCreateInfo A pointer to a VkBufferCreateInfo that describes the buffer to create.
    @param buffer[out] A pointer to a VkBuffer that will be created using the allocation.
    @param pAllocationCreateInfo A pointer to a GpResourceAllocationCreateInfo that describes the
    allocation.
    @param allocationOut[out] A pointer to GpResourceAllocation that represents the buffer
    allocation.
    */
    GPGMM_EXPORT VkResult
    gpCreateBuffer(GpResourceAllocator allocator,
                   const VkBufferCreateInfo* pBufferCreateInfo,
                   VkBuffer* pBuffer,
                   const GpResourceAllocationCreateInfo* pAllocationCreateInfo,
                   GpResourceAllocation* allocationOut);

    /** \brief  Destroy buffer allocation.

    @param allocator A GpResourceAllocator used to create the buffer and allocation.
    @param buffer A VkBuffer that was also created by the allocator.
    @param allocation A GpResourceAllocation that was created by the allocator.
    */
    GPGMM_EXPORT void gpDestroyBuffer(GpResourceAllocator allocator,
                                      VkBuffer buffer,
                                      GpResourceAllocation allocation);

    struct GpResourceAllocation_T final : public MemoryAllocation {
        GpResourceAllocation_T(const MemoryAllocation& allocation);
    };

    class Caps;
    struct GpResourceAllocator_T {
      public:
        static VkResult CreateAllocator(const GpCreateAllocatorInfo& info,
                                        GpResourceAllocator* allocatorOut);

        VkResult TryAllocateMemory(const VkMemoryRequirements& requirements,
                                   const GpResourceAllocationCreateInfo& allocationInfo,
                                   GpResourceAllocation* allocationOut);

        void DeallocateMemory(GpResourceAllocation allocation);

        void GetBufferMemoryRequirements(VkBuffer buffer, VkMemoryRequirements* requirementsOut);

        VkDevice GetDevice() const;
        VulkanFunctions GetFunctions() const;
        Caps* GetCaps() const;

      private:
        GpResourceAllocator_T(const GpCreateAllocatorInfo& info,
                              const VulkanFunctions& vulkanFunctions,
                              std::unique_ptr<Caps> caps);

        VkResult FindMemoryTypeIndex(uint32_t memoryTypeBits,
                                     const GpResourceAllocationCreateInfo& allocationInfo,
                                     uint32_t* memoryTypeIndexOut);

        VkDevice mDevice;
        VulkanFunctions mVulkanFunctions;
        std::unique_ptr<Caps> mCaps;

        std::vector<std::unique_ptr<MemoryAllocator>> mDeviceAllocatorsPerType;
        std::vector<VkMemoryType> mMemoryTypes;
    };

}}  // namespace gpgmm::vk

#endif  // GPGMM_VK_RESOURCEALLOCATORVK_H_
