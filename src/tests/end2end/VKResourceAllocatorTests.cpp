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

#include "gpgmm/common/SizeClass.h"
#include "tests/VKTest.h"

#include <gpgmm_vk.h>

using namespace gpgmm::vk;

static constexpr uint64_t kDefaultBufferSize = GPGMM_MB_TO_BYTES(4);

class VKResourceAllocatorTests : public VKTestBase, public ::testing::Test {
  protected:
    void SetUp() override {
        VKTestBase::SetUp();
    }

    void TearDown() override {
        VKTestBase::TearDown();
    }
};

TEST_F(VKResourceAllocatorTests, CreateAllocator) {
    GpResourceAllocator resourceAllocator;
    ASSERT_SUCCESS(gpCreateResourceAllocator(CreateBasicAllocatorInfo(), &resourceAllocator));
    gpDestroyResourceAllocator(resourceAllocator);
    ASSERT_SUCCESS(gpCreateResourceAllocator(CreateBasicAllocatorInfo(), nullptr));
}

TEST_F(VKResourceAllocatorTests, CreateBuffer) {
    GpResourceAllocator resourceAllocator;
    ASSERT_SUCCESS(gpCreateResourceAllocator(CreateBasicAllocatorInfo(), &resourceAllocator));

    VkBufferCreateInfo bufferInfo = {};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufferInfo.size = kDefaultBufferSize;

    GpResourceAllocationCreateInfo allocationInfo = {};

    VkBuffer buffer;
    GpResourceAllocation allocation;
    ASSERT_SUCCESS(
        gpCreateBuffer(resourceAllocator, &bufferInfo, &buffer, &allocationInfo, &allocation));

    gpDestroyBuffer(resourceAllocator, buffer, allocation);
    gpDestroyResourceAllocator(resourceAllocator);
}

TEST_F(VKResourceAllocatorTests, CreateImage) {
    GpResourceAllocator resourceAllocator;
    ASSERT_SUCCESS(gpCreateResourceAllocator(CreateBasicAllocatorInfo(), &resourceAllocator));

    VkImageCreateInfo imageInfo = {};
    imageInfo.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    imageInfo.extent.width = 1;
    imageInfo.extent.height = 1;
    imageInfo.extent.depth = 1;
    imageInfo.mipLevels = 1;
    imageInfo.arrayLayers = 1;
    imageInfo.format = VK_FORMAT_R8G8B8A8_UNORM;
    imageInfo.tiling = VK_IMAGE_TILING_OPTIMAL;
    imageInfo.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    imageInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    imageInfo.samples = VK_SAMPLE_COUNT_1_BIT;
    imageInfo.flags = 0;

    GpResourceAllocationCreateInfo allocationInfo = {};

    VkImage image;
    GpResourceAllocation allocation;
    ASSERT_SUCCESS(
        gpCreateImage(resourceAllocator, &imageInfo, &image, &allocationInfo, &allocation));

    gpDestroyImage(resourceAllocator, image, allocation);
    gpDestroyResourceAllocator(resourceAllocator);
}

TEST_F(VKResourceAllocatorTests, CreateBufferManyDeallocateAtEnd) {
    GpResourceAllocator resourceAllocator;
    ASSERT_SUCCESS(gpCreateResourceAllocator(CreateBasicAllocatorInfo(), &resourceAllocator));

    VkBufferCreateInfo bufferInfo = {};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;

    GpResourceAllocationCreateInfo allocationInfo = {};

    // TODO: Figure this value out
    constexpr uint64_t kBufferMemoryAlignment = GPGMM_KB_TO_BYTES(64);

    std::set<std::tuple<VkBuffer, GpResourceAllocation>> allocs = {};
    for (auto& alloc : GPGMMTestBase::GenerateTestAllocations(kBufferMemoryAlignment)) {
        VkBuffer buffer;
        GpResourceAllocation allocation = VK_NULL_HANDLE;
        bufferInfo.size = alloc.size;
        EXPECT_EQ(gpCreateBuffer(resourceAllocator, &bufferInfo, &buffer, &allocationInfo,
                                 &allocation) == VK_SUCCESS,
                  alloc.succeeds);
        if (allocation == VK_NULL_HANDLE) {
            continue;
        }

        ASSERT_NE(allocation, VK_NULL_HANDLE);
        EXPECT_TRUE(allocs.insert(std::make_tuple(buffer, allocation)).second);
    }

    for (auto& alloc : allocs) {
        gpDestroyBuffer(resourceAllocator, std::get<0>(alloc), std::get<1>(alloc));
    }

    gpDestroyResourceAllocator(resourceAllocator);
}
