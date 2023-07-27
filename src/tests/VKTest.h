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

#ifndef SRC_TESTS_VKTEST_H_
#define SRC_TESTS_VKTEST_H_

#include "tests/GPGMMTest.h"

#include "gpgmm/vk/VKPlatform.h"

#define ASSERT_FAILED(expr) ASSERT_TRUE((expr) != VK_SUCCESS)
#define ASSERT_SUCCESS(expr) ASSERT_TRUE((expr) == VK_SUCCESS)

#define EXPECT_FAILED(expr) EXPECT_TRUE((expr) != VK_SUCCESS)
#define EXPECT_SUCCEEDED(expr) EXPECT_TRUE((expr) == VK_SUCCESS)

namespace gpgmm::vk {

    struct GpAllocatorCreateInfo;

    class VKTestBase : public GPGMMTestBase {
      public:
        void SetUp();
        void TearDown();

        GpAllocatorCreateInfo CreateBasicAllocatorInfo() const;

      protected:
        VkDevice mDevice = VK_NULL_HANDLE;
        VkInstance mInstance = VK_NULL_HANDLE;
        VkPhysicalDevice mPhysicalDevice = VK_NULL_HANDLE;
    };

}  // namespace gpgmm::vk

#endif  // SRC_TESTS_VKTEST_H_
