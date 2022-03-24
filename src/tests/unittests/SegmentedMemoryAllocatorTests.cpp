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

#include "gpgmm/SegmentedMemoryAllocator.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

static constexpr uint64_t kDefaultMemorySize = 128u;
static constexpr uint64_t kDefaultMemoryAlignment = 1u;

TEST(SegmentedMemoryAllocatorTests, SingleHeap) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);

    std::unique_ptr<MemoryAllocation> invalidAllocation =
        allocator.TryAllocateMemory(0, kDefaultMemoryAlignment, false, false);
    ASSERT_EQ(invalidAllocation, nullptr);

    std::unique_ptr<MemoryAllocation> allocation =
        allocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
    EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    allocator.DeallocateMemory(std::move(allocation));
    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    allocator.ReleaseMemory();
    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);
}

TEST(SegmentedMemoryAllocatorTests, MultipleHeaps) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);

    std::unique_ptr<MemoryAllocation> firstAllocation =
        allocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(firstAllocation, nullptr);
    EXPECT_EQ(firstAllocation->GetSize(), kDefaultMemorySize);

    std::unique_ptr<MemoryAllocation> secondAllocation =
        allocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(secondAllocation, nullptr);
    EXPECT_EQ(secondAllocation->GetSize(), kDefaultMemorySize);

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    allocator.DeallocateMemory(std::move(firstAllocation));
    allocator.DeallocateMemory(std::move(secondAllocation));

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    allocator.ReleaseMemory();
    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);
}

TEST(SegmentedMemoryAllocatorTests, MultipleHeapsVariousSizes) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);

    // Append the 1st and 3rd segment, in sequence.
    uint64_t firstMemorySize = kDefaultMemorySize / 2;
    std::unique_ptr<MemoryAllocation> firstAllocation =
        allocator.TryAllocateMemory(firstMemorySize, kDefaultMemoryAlignment, false, false);
    EXPECT_EQ(firstAllocation->GetMethod(), AllocationMethod::kStandalone);
    ASSERT_NE(firstAllocation, nullptr);
    EXPECT_EQ(firstAllocation->GetSize(), firstMemorySize);

    uint64_t secondMemorySize = kDefaultMemorySize / 8;
    std::unique_ptr<MemoryAllocation> secondAllocation =
        allocator.TryAllocateMemory(secondMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(secondAllocation, nullptr);
    EXPECT_EQ(secondAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(secondAllocation->GetSize(), secondMemorySize);

    // Insert a 3rd segment in the middle or between the 1st and 2nd segment.
    uint64_t thirdMemorySize = kDefaultMemorySize / 4;
    std::unique_ptr<MemoryAllocation> thirdAllocation =
        allocator.TryAllocateMemory(thirdMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(thirdAllocation, nullptr);
    EXPECT_EQ(thirdAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(thirdAllocation->GetSize(), thirdMemorySize);

    // Insert a 4th segment at the end.
    uint64_t fourthMemorySize = kDefaultMemorySize;
    std::unique_ptr<MemoryAllocation> fourthAllocation =
        allocator.TryAllocateMemory(fourthMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(fourthAllocation, nullptr);
    EXPECT_EQ(fourthAllocation->GetSize(), fourthMemorySize);

    // Insert a 5th segment at the start.
    uint64_t fifthMemorySize = kDefaultMemorySize / 16;
    std::unique_ptr<MemoryAllocation> fifthAllocation =
        allocator.TryAllocateMemory(fifthMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(fifthAllocation, nullptr);
    EXPECT_EQ(fifthAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(fifthAllocation->GetSize(), fifthMemorySize);

    // Reuse the 3rd segment.
    std::unique_ptr<MemoryAllocation> sixthAllocation =
        allocator.TryAllocateMemory(thirdMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(sixthAllocation, nullptr);
    EXPECT_EQ(sixthAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(sixthAllocation->GetSize(), thirdMemorySize);

    // Reuse the 1st segment.
    std::unique_ptr<MemoryAllocation> seventhAllocation =
        allocator.TryAllocateMemory(firstMemorySize, kDefaultMemoryAlignment, false, false);
    ASSERT_NE(seventhAllocation, nullptr);
    EXPECT_EQ(seventhAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(seventhAllocation->GetSize(), firstMemorySize);

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 5u);

    allocator.DeallocateMemory(std::move(firstAllocation));
    allocator.DeallocateMemory(std::move(secondAllocation));
    allocator.DeallocateMemory(std::move(thirdAllocation));
    allocator.DeallocateMemory(std::move(fourthAllocation));
    allocator.DeallocateMemory(std::move(fifthAllocation));
    allocator.DeallocateMemory(std::move(sixthAllocation));
    allocator.DeallocateMemory(std::move(seventhAllocation));

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 5u);

    allocator.ReleaseMemory();

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 5u);
}

TEST(SegmentedMemoryAllocatorTests, ReuseFreedHeaps) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);
    {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);
}

TEST(SegmentedMemoryAllocatorTests, QueryInfo) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);

    std::unique_ptr<MemoryAllocation> allocation =
        allocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false, false);
    EXPECT_NE(allocation, nullptr);

    // Single memory block should be allocated.
    EXPECT_EQ(allocator.QueryInfo().UsedBlockCount, 0u);
    EXPECT_EQ(allocator.QueryInfo().UsedBlockUsage, 0u);
    EXPECT_EQ(allocator.QueryInfo().UsedMemoryCount, 1u);
    EXPECT_EQ(allocator.QueryInfo().UsedMemoryUsage, kDefaultMemorySize);
    EXPECT_EQ(allocator.QueryInfo().FreeMemoryUsage, 0u);

    allocator.DeallocateMemory(std::move(allocation));

    // Single memory is made available as free after being released.
    EXPECT_EQ(allocator.QueryInfo().UsedBlockCount, 0u);
    EXPECT_EQ(allocator.QueryInfo().UsedBlockUsage, 0u);
    EXPECT_EQ(allocator.QueryInfo().UsedMemoryCount, 0u);
    EXPECT_EQ(allocator.QueryInfo().UsedMemoryUsage, 0u);
    EXPECT_EQ(allocator.QueryInfo().FreeMemoryUsage, kDefaultMemorySize);
}
