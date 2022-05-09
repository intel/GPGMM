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

#include <gtest/gtest.h>

#include "gpgmm/common/ConditionalMemoryAllocator.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

class ConditionalMemoryAllocatorTests : public testing::Test {
  public:
    MEMORY_ALLOCATION_REQUEST CreateBasicRequest(uint64_t size, uint64_t alignment) {
        MEMORY_ALLOCATION_REQUEST request = {};
        request.SizeInBytes = size;
        request.Alignment = alignment;
        request.NeverAllocate = false;
        request.CacheSize = false;
        request.AlwaysPrefetch = false;
        return request;
    }
};

TEST_F(ConditionalMemoryAllocatorTests, Basic) {
    constexpr uint64_t conditionalSize = 16u;
    ConditionalMemoryAllocator alloc(std::make_unique<DummyMemoryAllocator>(),
                                     std::make_unique<DummyMemoryAllocator>(), conditionalSize);

    // Smaller allocation uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(CreateBasicRequest(4, 1));
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->GetInfo().UsedMemoryUsage, 4u);
        ASSERT_NE(allocation, nullptr);
        alloc.DeallocateMemory(std::move(allocation));
    }

    // Equal size allocation uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(CreateBasicRequest(16, 1));
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->GetInfo().UsedMemoryUsage, 16u);
        ASSERT_NE(allocation, nullptr);
        alloc.DeallocateMemory(std::move(allocation));
    }

    // Larger allocation uses secondAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(CreateBasicRequest(24, 1));
        ASSERT_EQ(alloc.GetSecondAllocatorForTesting()->GetInfo().UsedMemoryUsage, 24u);
        ASSERT_NE(allocation, nullptr);
        alloc.DeallocateMemory(std::move(allocation));
    }

    // Smaller allocation again uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(CreateBasicRequest(4, 1));
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->GetInfo().UsedMemoryUsage, 4u);
        ASSERT_NE(allocation, nullptr);
        alloc.DeallocateMemory(std::move(allocation));
    }

    // Larger allocation again uses secondAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(CreateBasicRequest(24, 1));
        ASSERT_EQ(alloc.GetSecondAllocatorForTesting()->GetInfo().UsedMemoryUsage, 24u);
        ASSERT_NE(allocation, nullptr);
        alloc.DeallocateMemory(std::move(allocation));
    }
}
