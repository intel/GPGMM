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
