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

#include "src/SegmentedMemoryAllocator.h"

using namespace gpgmm;

class SegmentedMemoryAllocatorTests : public testing::Test {
  protected:
    class DummyMemoryAllocator : public MemoryAllocator {
      public:
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t size,
                                                            uint64_t alignment,
                                                            bool neverAllocate) override {
            return std::make_unique<MemoryAllocation>(this, new MemoryBase(size));
        }

        void DeallocateMemory(MemoryAllocation* allocation) override {
            ASSERT(allocation != nullptr);
            delete allocation->GetMemory();
        }
    } mMemoryAllocator;

    static constexpr uint64_t kDefaultMemorySize = 128u;
    static constexpr uint64_t kDefaultMemoryAlignment = 1u;
};

TEST_F(SegmentedMemoryAllocatorTests, SingleHeap) {
    DummyMemoryAllocator memoryAllocator;
    SegmentedMemoryAllocator segmentedAllocator(&memoryAllocator, kDefaultMemoryAlignment);

    std::unique_ptr<MemoryAllocation> invalidAllocation =
        segmentedAllocator.TryAllocateMemory(0, kDefaultMemoryAlignment, false);
    ASSERT_EQ(invalidAllocation, nullptr);

    std::unique_ptr<MemoryAllocation> allocation =
        segmentedAllocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
    EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 0u);

    segmentedAllocator.DeallocateMemory(allocation.release());
    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 1u);

    segmentedAllocator.ReleaseMemory();
    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 0u);
}

TEST_F(SegmentedMemoryAllocatorTests, MultipleHeaps) {
    DummyMemoryAllocator memoryAllocator;
    SegmentedMemoryAllocator segmentedAllocator(&memoryAllocator, kDefaultMemoryAlignment);

    std::unique_ptr<MemoryAllocation> firstAllocation =
        segmentedAllocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(firstAllocation, nullptr);
    EXPECT_EQ(firstAllocation->GetSize(), kDefaultMemorySize);

    std::unique_ptr<MemoryAllocation> secondAllocation =
        segmentedAllocator.TryAllocateMemory(kDefaultMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(secondAllocation, nullptr);
    EXPECT_EQ(secondAllocation->GetSize(), kDefaultMemorySize);

    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 0u);

    segmentedAllocator.DeallocateMemory(firstAllocation.release());
    segmentedAllocator.DeallocateMemory(secondAllocation.release());

    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 2u);

    segmentedAllocator.ReleaseMemory();
    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 0u);
}

TEST_F(SegmentedMemoryAllocatorTests, MultipleHeapsVariousSizes) {
    DummyMemoryAllocator memoryAllocator;
    SegmentedMemoryAllocator segmentedAllocator(&memoryAllocator, kDefaultMemoryAlignment);

    // Append the 1st and 3rd segment, in sequence.
    uint64_t firstMemorySize = kDefaultMemorySize / 2;
    std::unique_ptr<MemoryAllocation> firstAllocation =
        segmentedAllocator.TryAllocateMemory(firstMemorySize, kDefaultMemoryAlignment, false);
    EXPECT_EQ(firstAllocation->GetMethod(), AllocationMethod::kStandalone);
    ASSERT_NE(firstAllocation, nullptr);
    EXPECT_EQ(firstAllocation->GetSize(), firstMemorySize);

    uint64_t secondMemorySize = kDefaultMemorySize / 8;
    std::unique_ptr<MemoryAllocation> secondAllocation =
        segmentedAllocator.TryAllocateMemory(secondMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(secondAllocation, nullptr);
    EXPECT_EQ(secondAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(secondAllocation->GetSize(), secondMemorySize);

    // Insert a 3rd segment in the middle or between the 1st and 2nd segment.
    uint64_t thirdMemorySize = kDefaultMemorySize / 4;
    std::unique_ptr<MemoryAllocation> thirdAllocation =
        segmentedAllocator.TryAllocateMemory(thirdMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(thirdAllocation, nullptr);
    EXPECT_EQ(thirdAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(thirdAllocation->GetSize(), thirdMemorySize);

    // Insert a 4th segment at the end.
    uint64_t fourthMemorySize = kDefaultMemorySize;
    std::unique_ptr<MemoryAllocation> fourthAllocation =
        segmentedAllocator.TryAllocateMemory(fourthMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(fourthAllocation, nullptr);
    EXPECT_EQ(fourthAllocation->GetSize(), fourthMemorySize);

    // Insert a 5th segment at the start.
    uint64_t fifthMemorySize = kDefaultMemorySize / 16;
    std::unique_ptr<MemoryAllocation> fifthAllocation =
        segmentedAllocator.TryAllocateMemory(fifthMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(fifthAllocation, nullptr);
    EXPECT_EQ(fifthAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(fifthAllocation->GetSize(), fifthMemorySize);

    // Reuse the 3rd segment.
    std::unique_ptr<MemoryAllocation> sixthAllocation =
        segmentedAllocator.TryAllocateMemory(thirdMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(sixthAllocation, nullptr);
    EXPECT_EQ(sixthAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(sixthAllocation->GetSize(), thirdMemorySize);

    // Reuse the 1st segment.
    std::unique_ptr<MemoryAllocation> seventhAllocation =
        segmentedAllocator.TryAllocateMemory(firstMemorySize, kDefaultMemoryAlignment, false);
    ASSERT_NE(seventhAllocation, nullptr);
    EXPECT_EQ(seventhAllocation->GetMethod(), AllocationMethod::kStandalone);
    EXPECT_EQ(seventhAllocation->GetSize(), firstMemorySize);

    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 0u);

    segmentedAllocator.DeallocateMemory(firstAllocation.release());
    segmentedAllocator.DeallocateMemory(secondAllocation.release());
    segmentedAllocator.DeallocateMemory(thirdAllocation.release());
    segmentedAllocator.DeallocateMemory(fourthAllocation.release());
    segmentedAllocator.DeallocateMemory(fifthAllocation.release());
    segmentedAllocator.DeallocateMemory(sixthAllocation.release());
    segmentedAllocator.DeallocateMemory(seventhAllocation.release());

    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 7u);

    segmentedAllocator.ReleaseMemory();

    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 0u);
}

TEST_F(SegmentedMemoryAllocatorTests, ReuseFreedHeaps) {
    DummyMemoryAllocator memoryAllocator;
    SegmentedMemoryAllocator segmentedAllocator(&memoryAllocator, kDefaultMemoryAlignment);
    {
        std::unique_ptr<MemoryAllocation> allocation = segmentedAllocator.TryAllocateMemory(
            kDefaultMemorySize, kDefaultMemoryAlignment, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
        segmentedAllocator.DeallocateMemory(allocation.release());
    }

    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 1u);

    {
        std::unique_ptr<MemoryAllocation> allocation = segmentedAllocator.TryAllocateMemory(
            kDefaultMemorySize, kDefaultMemoryAlignment, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kDefaultMemorySize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kStandalone);
        segmentedAllocator.DeallocateMemory(allocation.release());
    }

    EXPECT_EQ(segmentedAllocator.GetPoolSizeForTesting(), 1u);
}
