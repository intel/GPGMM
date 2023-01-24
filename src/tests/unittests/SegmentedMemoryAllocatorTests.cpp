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

#include "gpgmm/common/SegmentedMemoryAllocator.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

static constexpr uint64_t kDefaultMemorySize = 128u;
static constexpr uint64_t kDefaultMemoryAlignment = 1u;

MemoryAllocationRequest CreateBasicRequest(uint64_t size, uint64_t alignment) {
    MemoryAllocationRequest request = {};
    request.SizeInBytes = size;
    request.Alignment = alignment;
    request.NeverAllocate = false;
    request.AlwaysCacheSize = false;
    request.AlwaysPrefetch = false;
    return request;
}

TEST(SegmentedMemoryAllocatorTests, SingleHeap) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);

    std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
    EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    allocator.DeallocateMemory(std::move(allocation));
    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    EXPECT_EQ(allocator.ReleaseMemory(), kDefaultMemorySize);
    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);
}

TEST(SegmentedMemoryAllocatorTests, MultipleHeaps) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);

    std::unique_ptr<MemoryAllocation> firstAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(firstAllocation, nullptr);
    EXPECT_EQ(firstAllocation->GetSize(), kDefaultMemorySize);

    std::unique_ptr<MemoryAllocation> secondAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(secondAllocation, nullptr);
    EXPECT_EQ(secondAllocation->GetSize(), kDefaultMemorySize);

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    allocator.DeallocateMemory(std::move(firstAllocation));
    allocator.DeallocateMemory(std::move(secondAllocation));

    EXPECT_EQ(allocator.ReleaseMemory(kDefaultMemorySize), kDefaultMemorySize);
    EXPECT_EQ(allocator.ReleaseMemory(kDefaultMemorySize), kDefaultMemorySize);
    EXPECT_EQ(allocator.ReleaseMemory(kDefaultMemorySize), 0u);

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);
    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);
}

TEST(SegmentedMemoryAllocatorTests, MultipleHeapsVariousSizes) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);

    // Append the 1st and 3rd segment, in sequence.
    uint64_t firstMemorySize = kDefaultMemorySize / 2;
    std::unique_ptr<MemoryAllocation> firstAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(firstMemorySize, kDefaultMemoryAlignment));
    EXPECT_EQ(firstAllocation->GetMethod(), AllocationMethod::kStandalone);
    ASSERT_NE(firstAllocation, nullptr);
    EXPECT_EQ(firstAllocation->GetSize(), firstMemorySize);

    uint64_t secondMemorySize = kDefaultMemorySize / 8;
    std::unique_ptr<MemoryAllocation> secondAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(secondMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(secondAllocation, nullptr);
    EXPECT_EQ(secondAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(secondAllocation->GetSize(), secondMemorySize);

    // Insert a 3rd segment in the middle or between the 1st and 2nd segment.
    uint64_t thirdMemorySize = kDefaultMemorySize / 4;
    std::unique_ptr<MemoryAllocation> thirdAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(thirdMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(thirdAllocation, nullptr);
    EXPECT_EQ(thirdAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(thirdAllocation->GetSize(), thirdMemorySize);

    // Insert a 4th segment at the end.
    uint64_t fourthMemorySize = kDefaultMemorySize;
    std::unique_ptr<MemoryAllocation> fourthAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(fourthMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(fourthAllocation, nullptr);
    EXPECT_EQ(fourthAllocation->GetSize(), fourthMemorySize);

    // Insert a 5th segment at the start.
    uint64_t fifthMemorySize = kDefaultMemorySize / 16;
    std::unique_ptr<MemoryAllocation> fifthAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(fifthMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(fifthAllocation, nullptr);
    EXPECT_EQ(fifthAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(fifthAllocation->GetSize(), fifthMemorySize);

    // Reuse the 3rd segment.
    std::unique_ptr<MemoryAllocation> sixthAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(thirdMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(sixthAllocation, nullptr);
    EXPECT_EQ(sixthAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(sixthAllocation->GetSize(), thirdMemorySize);

    // Reuse the 1st segment.
    std::unique_ptr<MemoryAllocation> seventhAllocation = allocator.TryAllocateMemoryForTesting(
        CreateBasicRequest(firstMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(seventhAllocation, nullptr);
    EXPECT_EQ(seventhAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(seventhAllocation->GetSize(), firstMemorySize);

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 5u);

    // Release the first three allocations in order then release the others together.
    allocator.DeallocateMemory(std::move(firstAllocation));
    EXPECT_EQ(allocator.ReleaseMemory(firstMemorySize), firstMemorySize);

    allocator.DeallocateMemory(std::move(secondAllocation));
    EXPECT_EQ(allocator.ReleaseMemory(secondMemorySize), secondMemorySize);

    allocator.DeallocateMemory(std::move(thirdAllocation));
    EXPECT_EQ(allocator.ReleaseMemory(thirdMemorySize), thirdMemorySize);

    allocator.DeallocateMemory(std::move(fourthAllocation));
    allocator.DeallocateMemory(std::move(fifthAllocation));
    allocator.DeallocateMemory(std::move(sixthAllocation));
    allocator.DeallocateMemory(std::move(seventhAllocation));

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 5u);

    const uint64_t totalUnreleasedSize =
        fourthMemorySize + fifthMemorySize + thirdMemorySize + firstMemorySize;
    EXPECT_EQ(allocator.ReleaseMemory(totalUnreleasedSize), totalUnreleasedSize);

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 5u);
    EXPECT_EQ(allocator.ReleaseMemory(), 0u);
}

TEST(SegmentedMemoryAllocatorTests, ReuseFreedHeaps) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);
    {
        std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemoryForTesting(
            CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);

    {
        std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemoryForTesting(
            CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetSegmentSizeForTesting(), 1u);
}

TEST(SegmentedMemoryAllocatorTests, GetInfo) {
    SegmentedMemoryAllocator allocator(std::make_unique<DummyMemoryAllocator>(),
                                       kDefaultMemoryAlignment);

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
