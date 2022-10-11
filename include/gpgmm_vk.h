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

#ifndef INCLUDE_GPGMM_VK_H_
#define INCLUDE_GPGMM_VK_H_

// gpgmm_vk.h is the GMM interface implemented by GPGMM for Vulkan.
// This file should not be modified by downstream GMM clients or forks of GPGMM.
// Please consider submitting a pull-request to https://github.com/intel/gpgmm.
#include "gpgmm.h"

#ifndef GPGMM_VK_HEADERS_ALREADY_INCLUDED
#    include <vulkan/vulkan.h>
#endif

namespace gpgmm::vk {

    /** \struct GpResourceAllocator
    \brief Opaque handle to a allocator object.
    */
    VK_DEFINE_HANDLE(GpResourceAllocator)

    /** \struct GpResourceAllocation
    \brief Opaque handle to a resource allocation object.
    */
    VK_DEFINE_HANDLE(GpResourceAllocation)

    /** \enum GpAllocatorCreateFlags
    \brief Configures how allocators should be created.
    */
    enum GpAllocatorCreateFlags {
        /** \brief Disables all allocator flags.
         */
        GP_ALLOCATOR_CREATE_NONE = 0x0,

        /** \brief Disables pre-fetching of GPU memory.

        Should be only used for debugging and testing purposes.
        */
        GP_ALLOCATOR_CREATE_DISABLE_MEMORY_PREFETCH = 0x4,

        /** \brief Tell GPGMM to allocate exactly what is needed, and to de-allocate
        memory immediately once no longer needed (instead of re-using it).

        This is very slow and not recommended for general use but may be useful for running with the
        minimal possible GPU memory footprint or debugging OOM failures.
        */
        GP_ALLOCATOR_CREATE_ALWAYS_ON_DEMAND = 0x8,

        /** \brief Creates resource within budget.

        Requires the device extension VK_EXT_memory_budget to be supported before use.
        The instance specified in GpAllocatorCreateInfo is also required to support
        VK_KHR_get_physical_device_properties2.
        */
        GP_ALLOCATOR_CREATE_ALWAYS_IN_BUDGET = 0x10,
    };

    /** \enum GpAllocatorAlgorithm
    Specify the algorithms used for allocation.
    */
    enum GpAllocatorAlgorithm {
        /** \brief Use default allocation mechanism.

        Relies on internal heuristics to automatically determine the best allocation mechanism. The
        selection of algorithm depends on:

        1. The memory properties or flags specified by the user.
        2. The size the resource being created.
        3. The amount of available memory.

        In general, the most-efficent resource allocator will be attempted first (efficent
        being defined as fastest service-time to allocate/deallocate with smallest memory
        footprint), subject to other constraints. However, since it's impossible to predict all
        future memory accesses, allocation techniques that rely on amortization of GPU heaps may not
        prove to be faster as expected. Further experimentation is recommended.
        */
        GP_ALLOCATOR_ALGORITHM_DEFAULT = 0,

        /** \brief Use the slab allocation mechanism.

        Slab allocation allocates/deallocates in O(1) time using O(N * pageSize) space.

        Slab allocation does not suffer from internal fragmentation but could externally fragment
        when many unique request sizes are used.
        */
        GP_ALLOCATOR_ALGORITHM_SLAB = 1,

        /** \brief Use the buddy system mechanism.

        Buddy system allocate/deallocates in O(Log2) time using O(1) space.

        Buddy system suffers from internal fragmentation (ie. resources are not a power-of-two) but
        does not suffer from external fragmentation as much since the device memory size does not
        change.

        It is recommend to specify a preferredDeviceMemorySize large enough such that multiple
        requests can fit within the specified preferredDeviceMemorySize but not too large where
        creating the larger device memory becomes a bigger bottleneck.
        */
        GP_ALLOCATOR_ALGORITHM_BUDDY_SYSTEM = 2,

        /** \brief Recycles device memory of a size being specified.

        Fixed pools allocate/deallocate in O(1) time using O(N) space.

        Fixed-size pool limits recycling to device memorys equal to
        preferredDeviceMemorySize. A preferredDeviceMemorySize of zero is effectively
        equivelent to ALLOCATOR_FLAG_ALWAYS_ON_DEMAND.
        */
        GP_ALLOCATOR_ALGORITHM_FIXED_POOL = 3,

        /** \brief Recycles device memory of any size using multiple pools.

        Segmented pool allocate/deallocates in O(Log2) time using O(N * K) space.
        */
        GP_ALLOCATOR_ALGORITHM_SEGMENTED_POOL = 4,
    };

    struct VulkanFunctions;

    /** \struct GpAllocatorCreateInfo
    \brief Used to create allocator.
    */
    struct GpAllocatorCreateInfo {
        /** \brief Function pointer to Vulkan functions.

         There are 3 ways to specify Vulkan functions.
         1. Specify `gpgmm_vk_static_functions = true` and statically link agaisn't the Vulkan
         loader provided by GPGMM.
         2. Load Vulkan functions dynamically by specifying `gpgmm_vk_static_functions = false` and
         ONLY provide the instance and device functions, `vkGetInstanceProcAddr` and
         `vkGetDeviceProcAddr`. GPGMM will use those to load the remaining.
         3. Specify ALL the Vulkan functions. GPGMM will not import or load Vulkan function itself.
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

        /** \brief Flags used to configure allocator.
         */
        GpAllocatorCreateFlags flags;

        /** \brief Specifies the algorithm to use for sub-allocation.

        Used to evaluate how allocation implementations perform with various algorithms that
        sub-divide devie memory.

        Optional parameter. By default, the slab allocator is used.
        */
        GpAllocatorAlgorithm subAllocationAlgorithm = GP_ALLOCATOR_ALGORITHM_SLAB;

        /** \brief Specifies the algorithm to use for device memory pooling.

        Used to evaluate how allocation implementations perform with various algorithms that
        sub-divide device memorys.

        Optional parameter. By default, the slab allocator is used.
        */
        GpAllocatorAlgorithm poolAlgorithm = GP_ALLOCATOR_ALGORITHM_SEGMENTED_POOL;

        /** \brief Specifies the preferred size of device memory.

        The preferred size of the device memory is the minimum memory size to sub-allocate from.
        A larger device memory consumes more memory but could be faster for sub-allocation.

        Optional parameter. When 0 is specified, the API will automatically set the preferred
        device memory size to be a multiple of minimum device memory size allowed by Vulkan.
        */
        uint64_t preferredDeviceMemorySize;

        /** \brief Memory fragmentation limit, expressed as a percentage of the device memory size,
        that is acceptable to be wasted due to fragmentation.

        Fragmentation occurs when the allocation is larger then the resource size.
        This occurs when the type of resource (buffer or texture) and allocator have different
        alignment requirements. For example, a 192KB resource may need to allocate 256KB of
        allocated space, which is equivalent to a fragmentation limit of 33%.

        When |preferredDeviceMemorySize| is non-zero, the memoryFragmentationLimit could be
        exceeded. Also, the memoryFragmentationLimit should never be zero, as some fragmentation
        can occur.

        Optional parameter. When 0 is specified, the default fragmentation limit is 1/8th the
        device memory size.
        */
        double memoryFragmentationLimit;

        /** \brief Memory growth factor, expressed as a multipler of the device memory size
        that will monotonically increase.

        A factor value of 1.0 specifies no growth, where the device memory size is always determined
        by other limits or constraints. If no factor gets specified (or a value less than 1 is
        specified), GPGMM will allocate a device memory size with enough space to fit exactly one
        resource.

        Memory growth avoids the need to specify |preferredDeviceMemorySize|, which
        especially helps in situations where the resource size cannot be predicated (eg.
        user-defined), by allowing the device memory size to gradually increase in size
        per demand to achieve a balance of memory usage and performance.

        Optional parameter. When 0 is specified, the default of 1.25 is used (or 25% growth).
        */
        double memoryGrowthFactor;
    };

    /** \enum GpResourceAllocationCreateFlags
    Additional controls that modify allocations.
    */
    enum GpResourceAllocationCreateFlags {

        /** \brief Disables all allocation flags.

        Enabled by default.
        */
        GP_ALLOCATION_CREATE_NONE = 0x0,

        /** \brief  Disallow creating new device memory when creating a resource.

        Forbids creating new device memory when creating a resource. The created resource
        must use existing device memory or error. Effectively disables creating
        standalone allocations whose memory cannot be reused.
        */
        GP_ALLOCATION_CREATE_NEVER_ALLOCATE_MEMORY = 0x1,

        /** \brief Disallow creating multiple resource allocations from the same device memory.

        The created resource will always be allocated with it's own device memory.
        */
        GP_ALLOCATION_CREATE_NEVER_SUBALLOCATE_MEMORY = 0x4,

        /** \brief Prefetch memory for the next resource allocation.

        The call to prefetch is deferred to a seperate background thread by GPGMM which runs
        when the current allocation requested is completed. By default, GPGMM will automatically
        trigger prefetching based on heurstics. Prefetching enables more performance when
        allocating for large contiguous allocations. Should not be used with
        ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY.
        */
        GP_ALLOCATION_CREATE_ALWAYS_PREFETCH_MEMORY = 0x8,
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

    @param info A reference to GpAllocatorCreateInfo structure that describes the allocator.
    @param[out] allocatorOut Pointer to a memory block that recieves a pointer to the
    resource allocator. Pass NULL to test if allocator creation would succeed, but not actually
    create the allocator. If NULL is passed and allocator creating would succeed, VK_INCOMPLETE is
    returned.
    */
    GPGMM_EXPORT VkResult gpCreateResourceAllocator(const GpAllocatorCreateInfo& info,
                                                    GpResourceAllocator* allocatorOut);

    /** \brief  Destroy allocator.

    @param allocator A GpResourceAllocator to destroy.
    */
    GPGMM_EXPORT void gpDestroyResourceAllocator(GpResourceAllocator allocator);

    /** \brief  Create a buffer allocation.

    @param allocator A GpResourceAllocator used to create the buffer and allocation.
    @param pBufferCreateInfo A pointer to a VkBufferCreateInfo that describes the buffer to create.
    @param pBuffer A pointer to a VkBuffer that will be created using the allocation.
    @param pAllocationCreateInfo A pointer to a GpResourceAllocationCreateInfo that describes the
    allocation.
    @param[out] allocationOut A pointer to GpResourceAllocation that represents the buffer
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

    /** \brief  Create a image allocation.

    @param allocator A GpResourceAllocator used to create the image and allocation.
    @param pImageCreateInfo A pointer to a VkImageCreateInfo that describes the image to create.
    @param pImage A pointer to a VkImage that will be created using the allocation.
    @param pAllocationCreateInfo A pointer to a GpResourceAllocationCreateInfo that describes the
    allocation.
    @param[out] allocationOut A pointer to GpResourceAllocation that represents the image
    allocation.
    */
    GPGMM_EXPORT VkResult gpCreateImage(GpResourceAllocator allocator,
                                        const VkImageCreateInfo* pImageCreateInfo,
                                        VkImage* pImage,
                                        const GpResourceAllocationCreateInfo* pAllocationCreateInfo,
                                        GpResourceAllocation* allocationOut);

    /** \brief  Destroy image allocation.

    @param allocator A GpResourceAllocator used to create the image and allocation.
    @param image A VkImage that was also created by the allocator.
    @param allocation A GpResourceAllocation that was created by the allocator.
    */
    GPGMM_EXPORT void gpDestroyImage(GpResourceAllocator allocator,
                                     VkImage image,
                                     GpResourceAllocation allocation);

}  // namespace gpgmm::vk

#endif  // INCLUDE_GPGMM_VK_H_
