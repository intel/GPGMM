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

#include <gtest/gtest.h>

#include "gpgmm/common/PooledMemoryAllocator.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

static constexpr uint64_t kDefaultMemorySize = 128u;
static constexpr uint64_t kDefaultMemoryAlignment = 1u;

class PooledMemoryAllocatorTests : public testing::Test {
  public:
    MemoryAllocationRequest CreateBasicRequest(uint64_t size,
                                               uint64_t alignment,
                                               bool neverAllocate = false) {
        MemoryAllocationRequest request = {};
        request.SizeInBytes = size;
        request.Alignment = alignment;
        request.NeverAllocate = neverAllocate;
        request.AlwaysCacheSize = false;
        request.AlwaysPrefetch = false;
        request.AvailableForAllocation = kInvalidSize;
        return request;
    }
};

TEST_F(PooledMemoryAllocatorTests, SingleHeap) {
    PooledMemoryAllocator allocator(kDefaultMemorySize, kDefaultMemoryAlignment,
                                    std::make_unique<DummyMemoryAllocator>());

    std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
    EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(allocator.GetStats().UsedMemoryCount, 1u);

    allocator.DeallocateMemory(std::move(allocation));
    EXPECT_EQ(allocator.GetStats().UsedMemoryCount, 0u);

    EXPECT_EQ(allocator.ReleaseMemory(), kDefaultMemorySize);
    EXPECT_EQ(allocator.GetStats().FreeMemoryUsage, 0u);
}

TEST_F(PooledMemoryAllocatorTests, MultipleHeaps) {
    PooledMemoryAllocator allocator(kDefaultMemorySize, kDefaultMemoryAlignment,
                                    std::make_unique<DummyMemoryAllocator>());

    std::unique_ptr<MemoryAllocation> firstAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(firstAllocation, nullptr);
    EXPECT_EQ(firstAllocation->GetSize(), kDefaultMemorySize);

    std::unique_ptr<MemoryAllocation> secondAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(secondAllocation, nullptr);
    EXPECT_EQ(secondAllocation->GetSize(), kDefaultMemorySize);

    EXPECT_EQ(allocator.GetStats().UsedMemoryCount, 2u);

    allocator.DeallocateMemory(std::move(firstAllocation));
    allocator.DeallocateMemory(std::move(secondAllocation));

    EXPECT_EQ(allocator.ReleaseMemory(kDefaultMemorySize), kDefaultMemorySize);
    EXPECT_EQ(allocator.ReleaseMemory(kDefaultMemorySize), kDefaultMemorySize);
    EXPECT_EQ(allocator.ReleaseMemory(kDefaultMemorySize), 0u);

    EXPECT_EQ(allocator.GetStats().UsedMemoryCount, 0u);
    EXPECT_EQ(allocator.GetStats().FreeMemoryUsage, 0u);
}

TEST_F(PooledMemoryAllocatorTests, ReuseFreedHeaps) {
    PooledMemoryAllocator allocator(kDefaultMemorySize, kDefaultMemoryAlignment,
                                    std::make_unique<DummyMemoryAllocator>());
    {
        std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemoryForTesting(
            CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetStats().FreeMemoryUsage, kDefaultMemorySize);

    {
        std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemoryForTesting(
            CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetStats().FreeMemoryUsage, kDefaultMemorySize);
}

TEST_F(PooledMemoryAllocatorTests, GetInfo) {
    PooledMemoryAllocator allocator(kDefaultMemorySize, kDefaultMemoryAlignment,
                                    std::make_unique<DummyMemoryAllocator>());

    std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    EXPECT_NE(allocation, nullptr);

    // Single memory block should be allocated.
    EXPECT_EQ(allocator.GetStats().UsedBlockCount, 0u);
    EXPECT_EQ(allocator.GetStats().UsedBlockUsage, 0u);
    EXPECT_EQ(allocator.GetStats().UsedMemoryCount, 1u);
    EXPECT_EQ(allocator.GetStats().UsedMemoryUsage, kDefaultMemorySize);
    EXPECT_EQ(allocator.GetStats().FreeMemoryUsage, 0u);

    allocator.DeallocateMemory(std::move(allocation));

    // Single memory is made available as free after being released.
    EXPECT_EQ(allocator.GetStats().UsedBlockCount, 0u);
    EXPECT_EQ(allocator.GetStats().UsedBlockUsage, 0u);
    EXPECT_EQ(allocator.GetStats().UsedMemoryCount, 0u);
    EXPECT_EQ(allocator.GetStats().UsedMemoryUsage, 0u);
    EXPECT_EQ(allocator.GetStats().FreeMemoryUsage, kDefaultMemorySize);
}
