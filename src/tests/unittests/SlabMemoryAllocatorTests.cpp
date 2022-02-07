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

#include "gpgmm/LIFOMemoryPool.h"
#include "gpgmm/PooledMemoryAllocator.h"
#include "gpgmm/SlabMemoryAllocator.h"
#include "gpgmm/common/Math.h"
#include "tests/DummyMemoryAllocator.h"

#include <set>
#include <vector>

using namespace gpgmm;

static constexpr uint64_t kDefaultMemorySize = 128u;
static constexpr uint64_t kDefaultSlabAlignment = 1u;

// Verify a single resource allocation in a single slab.
TEST(SlabMemoryAllocatorTests, SingleSlab) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    // Verify allocation cannot be greater then the block size.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultMemorySize,
                                      kDefaultSlabAlignment, dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize * 2, 1, false);
        ASSERT_EQ(allocation, nullptr);

        allocation = allocator.TryAllocateMemory(22, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kBlockSize);

        allocator.DeallocateMemory(allocation.release());
    }

    // Verify allocation equal to the slab size always succeeds.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kMemorySize = 0;  // deduces size from block size.
        constexpr uint64_t kMaxSlabSize = kBlockSize;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kMemorySize, kDefaultSlabAlignment,
                                      dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
    }

    // Verify allocation cannot exceed the fragmentation threshold.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kMaxSlabSize = 32;
        constexpr uint64_t kMemorySize = 0;  // deduce slab size based on block size.
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kMemorySize, kDefaultSlabAlignment,
                                      dummyMemoryAllocator.get());

        // Max allocation cannot be more than 1/8th the max slab size or 4 bytes.
        // Since a 10 byte allocation requires a 128 byte slab, allocation should always fail.
        std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemory(10, 1, false);
        ASSERT_EQ(allocation, nullptr);

        // Re-attempt with 4 byte allocation that is under the fragmentation limit.
        allocation = allocator.TryAllocateMemory(4, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
    }

    // Verify allocation succeeds when specifying a slab size.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kMemorySize = 32;
        constexpr uint64_t kMaxSlabSize = 128;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kMemorySize, kDefaultSlabAlignment,
                                      dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
        EXPECT_GE(allocation->GetMemory()->GetSize(), kMemorySize);
    }

    // Verify allocation succeeds when specifying a NPOT slab size.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kMemorySize = 33;
        constexpr uint64_t kMaxSlabSize = 128;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kMemorySize, kDefaultSlabAlignment,
                                      dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
        EXPECT_GE(allocation->GetMemory()->GetSize(), kMemorySize);
    }
}

// Verify a single resource allocation in multiple slabs.
TEST(SlabMemoryAllocatorTests, MultipleSlabs) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMaxSlabSize = 512;
    SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultMemorySize,
                                  kDefaultSlabAlignment, dummyMemoryAllocator.get());
    // Fill up exactly two 256B slabs (1/8th of 256B is 32B blocks).
    uint64_t slabSize = 256;
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
    for (uint32_t blocki = 0; blocki < (slabSize * 2 / kBlockSize); blocki++) {
        std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemory(22, 1, false);
        ASSERT_NE(allocation, nullptr);
        allocations.push_back(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetPoolSizeForTesting(), 2u);

    // Free both slabs.
    for (auto& allocation : allocations) {
        allocator.DeallocateMemory(allocation.release());
    }

    EXPECT_EQ(allocator.GetPoolSizeForTesting(), 0u);
}

// Verify a very large allocation does not overflow.
TEST(SlabMemoryAllocatorTests, AllocationOverflow) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMaxSlabSize = 512;
    SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultMemorySize,
                                  kDefaultSlabAlignment, dummyMemoryAllocator.get());

    constexpr uint64_t largeBlock = (1ull << 63) + 1;
    std::unique_ptr<MemoryAllocation> invalidAllocation =
        allocator.TryAllocateMemory(largeBlock, kDefaultSlabAlignment, /*neverAllocate*/ true);
    ASSERT_EQ(invalidAllocation, nullptr);
}

// Verify slab will be reused from a pool.
TEST(SlabMemoryAllocatorTests, ReuseSlabs) {
    LIFOMemoryPool memoryPool;
    std::unique_ptr<PooledMemoryAllocator> poolAllocator = std::make_unique<PooledMemoryAllocator>(
        std::make_unique<DummyMemoryAllocator>(), &memoryPool);

    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMaxSlabSize = 512;
    SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultMemorySize,
                                  kDefaultSlabAlignment, poolAllocator.get());

    std::set<MemoryBase*> slabMemory = {};
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};

    // Count by slabs (vs number of allocations) to ensure there are exactly |kNumOfSlabs| worth of
    // allocations. Otherwise, the slab may be reused if not full.
    constexpr uint32_t kNumOfSlabs = 10;

    // Allocate |kNumOfSlabs| worth.
    while (slabMemory.size() < kNumOfSlabs) {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, /*neverAllocate*/ false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kBlockSize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        slabMemory.insert(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    ASSERT_EQ(memoryPool.GetPoolSize(), 0u);

    // Return the allocations to the pool.
    for (auto& allocation : allocations) {
        ASSERT_NE(allocation, nullptr);
        allocator.DeallocateMemory(allocation.release());
    }

    ASSERT_EQ(memoryPool.GetPoolSize(), kNumOfSlabs);

    memoryPool.ReleasePool();
}

TEST(SlabMemoryAllocatorTests, MultipleSlabsSameSize) {
    constexpr uint64_t kMinkBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = 128;
    constexpr uint64_t kMemorySize = 0;  // deduce slab size based on block size.
    SlabCacheAllocator allocator(kMinkBlockSize, kMaxSlabSize, kMemorySize, kDefaultSlabAlignment,
                                 std::make_unique<DummyMemoryAllocator>());

    std::unique_ptr<MemoryAllocation> firstAllocation = allocator.TryAllocateMemory(22, 1, false);
    ASSERT_NE(firstAllocation, nullptr);

    std::unique_ptr<MemoryAllocation> secondAllocation = allocator.TryAllocateMemory(22, 1, false);
    ASSERT_NE(secondAllocation, nullptr);

    allocator.DeallocateMemory(firstAllocation.release());
    allocator.DeallocateMemory(secondAllocation.release());

    std::unique_ptr<MemoryAllocation> thirdAllocation = allocator.TryAllocateMemory(44, 1, false);
    ASSERT_NE(thirdAllocation, nullptr);

    std::unique_ptr<MemoryAllocation> fourthAllocation = allocator.TryAllocateMemory(44, 1, false);
    ASSERT_NE(fourthAllocation, nullptr);

    allocator.DeallocateMemory(thirdAllocation.release());
    allocator.DeallocateMemory(fourthAllocation.release());
}

TEST(SlabMemoryAllocatorTests, MultipleSlabsVariableSizes) {
    constexpr uint64_t kMinkBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = 128;
    constexpr uint64_t kMemorySize = 0;  // deduce slab size based on block size.
    SlabCacheAllocator allocator(kMinkBlockSize, kMaxSlabSize, kMemorySize, kDefaultSlabAlignment,
                                 std::make_unique<DummyMemoryAllocator>());
    {
        constexpr uint64_t allocationSize = 22;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(allocationSize, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), AlignTo(allocationSize, kMinkBlockSize));

        allocator.DeallocateMemory(allocation.release());
    }
    {
        constexpr uint64_t allocationSize = 44;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(allocationSize, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), AlignTo(allocationSize, kMinkBlockSize));

        allocator.DeallocateMemory(allocation.release());
    }
    {
        constexpr uint64_t allocationSize = 88;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(allocationSize, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), AlignTo(allocationSize, kMinkBlockSize));

        allocator.DeallocateMemory(allocation.release());
    }

    EXPECT_EQ(allocator.GetPoolSizeForTesting(), 0u);
}
