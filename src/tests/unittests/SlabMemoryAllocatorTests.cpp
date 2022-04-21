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

#include "gpgmm/BuddyMemoryAllocator.h"
#include "gpgmm/LIFOMemoryPool.h"
#include "gpgmm/PooledMemoryAllocator.h"
#include "gpgmm/SlabMemoryAllocator.h"
#include "gpgmm/common/Math.h"
#include "tests/DummyMemoryAllocator.h"

#include <set>
#include <vector>

using namespace gpgmm;

static constexpr uint64_t kDefaultSlabSize = 128u;
static constexpr uint64_t kDefaultSlabAlignment = 1u;
static constexpr double kDefaultSlabFragmentationLimit = 0.125;
static constexpr bool kDefaultPrefetchSlab = false;

// Verify allocation in a single slab.
TEST(SlabMemoryAllocatorTests, SingleSlab) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    // Verify allocation cannot be greater then the block size.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kDefaultPrefetchSlab, dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize * 2, 1, false, false, false);
        ASSERT_EQ(allocation, nullptr);

        allocation = allocator.TryAllocateMemory(22, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kBlockSize);

        allocator.DeallocateMemory(std::move(allocation));
    }

    // Verify allocation equal to the slab size always succeeds.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
        constexpr uint64_t kMaxSlabSize = kBlockSize;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                      dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
    }

    // Verify allocation cannot exceed the fragmentation threshold.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kMaxSlabSize = 32;
        constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                      dummyMemoryAllocator.get());

        // Max allocation cannot be more than 1/8th the max slab size or 4 bytes.
        // Since a 10 byte allocation requires a 128 byte slab, allocation should always fail.
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(10, 1, false, false, false);
        ASSERT_EQ(allocation, nullptr);

        // Re-attempt with an allocation that is under the fragmentation limit.
        allocation = allocator.TryAllocateMemory(14, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
    }

    // Verify allocation succeeds when specifying a slab size.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kSlabSize = 32;
        constexpr uint64_t kMaxSlabSize = 128;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                      dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
        EXPECT_GE(allocation->GetMemory()->GetSize(), kSlabSize);
    }

    // Verify allocation succeeds when specifying a NPOT slab size.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kSlabSize = 33;
        constexpr uint64_t kMaxSlabSize = 128;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                      dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
        EXPECT_GE(allocation->GetMemory()->GetSize(), kSlabSize);
    }

    // Verify requesting an allocation without memory will not return a valid allocation.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kDefaultPrefetchSlab, dummyMemoryAllocator.get());

        EXPECT_EQ(allocator.TryAllocateMemory(kBlockSize, 1, true, false, false), nullptr);
        EXPECT_EQ(allocator.TryAllocateMemory(kBlockSize / 2, 1, true, false, false), nullptr);
        EXPECT_EQ(allocator.TryAllocateMemory(kBlockSize / 4, 1, true, false, false), nullptr);
    }
}

// Verify allocation in multiple slabs.
TEST(SlabMemoryAllocatorTests, MultipleSlabs) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    // Fill up exactly N slabs (allocation = block = slab size).
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;

        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, /*slabSize*/ kBlockSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kDefaultPrefetchSlab, dummyMemoryAllocator.get());
        const uint64_t kNumOfSlabs = 12;
        std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
        for (uint32_t slabi = 0; slabi < kNumOfSlabs; slabi++) {
            std::unique_ptr<MemoryAllocation> allocation =
                allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
            ASSERT_NE(allocation, nullptr);
            allocations.push_back(std::move(allocation));
        }

        EXPECT_EQ(allocator.GetSlabSizeForTesting(), kNumOfSlabs);

        for (auto& allocation : allocations) {
            allocator.DeallocateMemory(std::move(allocation));
        }

        EXPECT_EQ(allocator.GetSlabSizeForTesting(), 0u);
    }

    // Fill up slabs through pre-allocation (allocation < block < slab size).
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;

        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kDefaultPrefetchSlab, dummyMemoryAllocator.get());
        // Fill up exactly two 128B slabs.
        std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
        for (uint32_t blocki = 0; blocki < (kDefaultSlabSize * 2 / kBlockSize); blocki++) {
            std::unique_ptr<MemoryAllocation> allocation =
                allocator.TryAllocateMemory(22, 1, false, false, false);
            ASSERT_NE(allocation, nullptr);
            allocations.push_back(std::move(allocation));
        }

        EXPECT_EQ(allocator.GetSlabSizeForTesting(), 2u);

        // Free both slabs.
        for (auto& allocation : allocations) {
            allocator.DeallocateMemory(std::move(allocation));
        }

        EXPECT_EQ(allocator.GetSlabSizeForTesting(), 0u);
    }

    // Verify slabs are reused in LIFO.
    {
        constexpr uint64_t kBlockSize = 64;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kDefaultPrefetchSlab, dummyMemoryAllocator.get());

        // Both allocation A and B go in Slab A, which will become full.
        std::unique_ptr<MemoryAllocation> allocationAinSlabA =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocationAinSlabA, nullptr);

        std::unique_ptr<MemoryAllocation> allocationBInSlabA =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocationAinSlabA, nullptr);

        EXPECT_EQ(allocationAinSlabA->GetMemory(), allocationBInSlabA->GetMemory());

        // Allocation C and D go in Slab B, which will become full.
        std::unique_ptr<MemoryAllocation> allocationCInSlabB =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocationCInSlabB, nullptr);

        EXPECT_NE(allocationBInSlabA->GetMemory(), allocationCInSlabB->GetMemory());

        std::unique_ptr<MemoryAllocation> allocationDInSlabB =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocationDInSlabB, nullptr);

        EXPECT_EQ(allocationCInSlabB->GetMemory(), allocationDInSlabB->GetMemory());

        // Allocation E and F goes in Slab C, which will become full.
        std::unique_ptr<MemoryAllocation> allocationEInSlabC =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocationEInSlabC, nullptr);

        EXPECT_NE(allocationDInSlabB->GetMemory(), allocationEInSlabC->GetMemory());

        std::unique_ptr<MemoryAllocation> allocationFInSlabC =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocationFInSlabC, nullptr);

        EXPECT_EQ(allocationEInSlabC->GetMemory(), allocationFInSlabC->GetMemory());

        // Free list: []
        // Full list: C -> B -> A.

        allocator.DeallocateMemory(std::move(allocationAinSlabA));
        allocator.DeallocateMemory(std::move(allocationCInSlabB));

        // Free list: B -> A.
        // Full list: C.

        std::unique_ptr<MemoryAllocation> allocationGInSlabB =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocationGInSlabB, nullptr);
        EXPECT_EQ(allocationDInSlabB->GetMemory(), allocationGInSlabB->GetMemory());

        // Free list: A.
        // Full list: B -> C.

        std::unique_ptr<MemoryAllocation> allocationHInSlabA =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocationGInSlabB, nullptr);

        EXPECT_EQ(allocationBInSlabA->GetMemory(), allocationHInSlabA->GetMemory());

        // Free list: [].
        // Full list: A -> B -> C.

        allocator.DeallocateMemory(std::move(allocationHInSlabA));
        allocator.DeallocateMemory(std::move(allocationBInSlabA));

        allocator.DeallocateMemory(std::move(allocationGInSlabB));
        allocator.DeallocateMemory(std::move(allocationDInSlabB));

        allocator.DeallocateMemory(std::move(allocationEInSlabC));
        allocator.DeallocateMemory(std::move(allocationFInSlabC));

        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
    }
}

// Verify a very large allocation does not overflow.
TEST(SlabMemoryAllocatorTests, AllocationOverflow) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMaxSlabSize = 512;
    SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                  kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                  dummyMemoryAllocator.get());

    constexpr uint64_t largeBlock = (1ull << 63) + 1;
    std::unique_ptr<MemoryAllocation> invalidAllocation =
        allocator.TryAllocateMemory(largeBlock, kDefaultSlabAlignment, true, false, false);
    ASSERT_EQ(invalidAllocation, nullptr);
}

// Verify slab will be reused from a pool.
TEST(SlabMemoryAllocatorTests, ReuseSlabs) {
    LIFOMemoryPool pool(kDefaultSlabSize);
    std::unique_ptr<PooledMemoryAllocator> poolAllocator =
        std::make_unique<PooledMemoryAllocator>(std::make_unique<DummyMemoryAllocator>(), &pool);

    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMaxSlabSize = 512;
    SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                  kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                  poolAllocator.get());

    std::set<MemoryBase*> slabMemory = {};
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};

    // Count by slabs (vs number of allocations) to ensure there are exactly |kNumOfSlabs| worth of
    // allocations. Otherwise, the slab may be reused if not full.
    constexpr uint32_t kNumOfSlabs = 10;

    // Allocate |kNumOfSlabs| worth.
    while (slabMemory.size() < kNumOfSlabs) {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kBlockSize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        slabMemory.insert(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    ASSERT_EQ(pool.GetPoolSize(), 0u);

    // Return the allocations to the pool.
    for (auto& allocation : allocations) {
        ASSERT_NE(allocation, nullptr);
        allocator.DeallocateMemory(std::move(allocation));
    }

    ASSERT_EQ(pool.GetPoolSize(), kNumOfSlabs);

    pool.ReleasePool();
}

TEST(SlabMemoryAllocatorTests, GetInfo) {
    // Test slab allocator.
    {
        std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
            std::make_unique<DummyMemoryAllocator>();

        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kDefaultPrefetchSlab, dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        EXPECT_NE(allocation, nullptr);

        // Single sub-allocation within a slab should be allocated.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, kBlockSize);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, kDefaultSlabSize);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, 0u);

        allocator.DeallocateMemory(std::move(allocation));

        // Both the sub-allocation and slab should be released.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, 0u);
    }

    // Test slab + pool allocator.
    {
        LIFOMemoryPool pool(kDefaultSlabSize);
        std::unique_ptr<PooledMemoryAllocator> poolAllocator =
            std::make_unique<PooledMemoryAllocator>(std::make_unique<DummyMemoryAllocator>(),
                                                    &pool);

        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kDefaultPrefetchSlab, poolAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        EXPECT_NE(allocation, nullptr);

        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, kBlockSize);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, kDefaultSlabSize);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, 0u);

        allocator.DeallocateMemory(std::move(allocation));

        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, kDefaultSlabSize);
    }
}

TEST(SlabCacheAllocatorTests, SingleSlabMultipleSize) {
    constexpr uint64_t kMinBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = 256;
    constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
    SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                 std::make_unique<DummyMemoryAllocator>());

    // Verify requesting an allocation without memory will not return a valid allocation.
    {
        EXPECT_EQ(allocator.TryAllocateMemory(kMinBlockSize, 1, true, false, false), nullptr);
        EXPECT_EQ(allocator.TryAllocateMemory(kMinBlockSize * 2, 1, true, false, false), nullptr);
    }
}

TEST(SlabCacheAllocatorTests, MultipleSlabsSameSize) {
    constexpr uint64_t kMinBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = 256;
    constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
    SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                 std::make_unique<DummyMemoryAllocator>());

    std::unique_ptr<MemoryAllocation> firstAllocation =
        allocator.TryAllocateMemory(22, 1, false, false, false);
    ASSERT_NE(firstAllocation, nullptr);

    std::unique_ptr<MemoryAllocation> secondAllocation =
        allocator.TryAllocateMemory(22, 1, false, false, false);
    ASSERT_NE(secondAllocation, nullptr);

    allocator.DeallocateMemory(std::move(firstAllocation));
    allocator.DeallocateMemory(std::move(secondAllocation));

    std::unique_ptr<MemoryAllocation> thirdAllocation =
        allocator.TryAllocateMemory(44, 1, false, false, false);
    ASSERT_NE(thirdAllocation, nullptr);

    std::unique_ptr<MemoryAllocation> fourthAllocation =
        allocator.TryAllocateMemory(44, 1, false, false, false);
    ASSERT_NE(fourthAllocation, nullptr);

    allocator.DeallocateMemory(std::move(thirdAllocation));
    allocator.DeallocateMemory(std::move(fourthAllocation));
}

TEST(SlabCacheAllocatorTests, MultipleSlabsVariableSizes) {
    constexpr uint64_t kMinBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = 256;
    constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
    SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                 std::make_unique<DummyMemoryAllocator>());
    {
        constexpr uint64_t allocationSize = 22;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(allocationSize, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), AlignTo(allocationSize, kMinBlockSize));

        allocator.DeallocateMemory(std::move(allocation));
    }
    {
        constexpr uint64_t allocationSize = 44;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(allocationSize, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), AlignTo(allocationSize, kMinBlockSize));

        allocator.DeallocateMemory(std::move(allocation));
    }
    {
        constexpr uint64_t allocationSize = 88;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(allocationSize, 1, false, false, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), AlignTo(allocationSize, kMinBlockSize));

        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetSlabCacheSizeForTesting(), 0u);
}

TEST(SlabCacheAllocatorTests, SingleSlabInBuddy) {
    // 1. Create a buddy allocator as the back-end allocator.
    // 2. Create a slab allocator as the front-end allocator.
    constexpr uint64_t kMaxBlockSize = 256;
    constexpr uint64_t kMinBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = kMaxBlockSize;
    constexpr uint64_t kSlabSize = kDefaultSlabSize / 8;
    SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                 std::make_unique<BuddyMemoryAllocator>(
                                     kMaxBlockSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                     std::make_unique<DummyMemoryAllocator>()));

    std::unique_ptr<MemoryAllocation> allocation =
        allocator.TryAllocateMemory(kMinBlockSize, 1, false, false, false);
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetOffset(), 0u);
    EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
    EXPECT_GE(allocation->GetSize(), kMinBlockSize);

    allocator.DeallocateMemory(std::move(allocation));
}

TEST(SlabCacheAllocatorTests, MultipleSlabsInBuddy) {
    // 1. Create a buddy allocator as the back-end allocator.
    // 2. Create a slab allocator as the front-end allocator.
    constexpr uint64_t kMaxBlockSize = 256;
    constexpr uint64_t kMinBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = kMaxBlockSize;
    constexpr uint64_t kSlabSize = kDefaultSlabSize / 8;
    SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                 std::make_unique<BuddyMemoryAllocator>(
                                     kMaxBlockSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                     std::make_unique<DummyMemoryAllocator>()));

    // Verify multiple slab-buddy sub-allocation in the same slab are allocated contigiously.
    {
        constexpr uint64_t allocationSize = kMinBlockSize * 2;
        std::unique_ptr<MemoryAllocation> firstAllocation =
            allocator.TryAllocateMemory(allocationSize, 1, false, false, false);
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetOffset(), 0u);
        EXPECT_EQ(firstAllocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(firstAllocation->GetSize(), allocationSize);

        EXPECT_EQ(firstAllocation->GetMemory()->GetSize(), kDefaultSlabSize);

        std::unique_ptr<MemoryAllocation> secondAllocation =
            allocator.TryAllocateMemory(allocationSize, 1, false, false, false);
        ASSERT_NE(secondAllocation, nullptr);
        EXPECT_EQ(secondAllocation->GetOffset(), allocationSize);
        EXPECT_EQ(secondAllocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(secondAllocation->GetSize(), allocationSize);

        EXPECT_EQ(secondAllocation->GetMemory()->GetSize(), kDefaultSlabSize);

        allocator.DeallocateMemory(std::move(firstAllocation));
        allocator.DeallocateMemory(std::move(secondAllocation));
    }

    // Verify multiple slab-buddy sub-allocations across buddies are allocated non-contigiously.
    {
        // Fill the first buddy up with slabs.
        std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
        for (uint32_t i = 0; i < kDefaultSlabSize / kSlabSize; i++) {
            std::unique_ptr<MemoryAllocation> allocation =
                allocator.TryAllocateMemory(kSlabSize, 1, false, false, false);
            ASSERT_NE(allocation, nullptr);
            EXPECT_EQ(allocation->GetOffset(), i * kSlabSize);
            EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
            EXPECT_GE(allocation->GetSize(), kSlabSize);
            allocations.push_back(std::move(allocation));
        }

        // Next slab-buddy sub-allocation must be in the second buddy.
        std::unique_ptr<MemoryAllocation> firstSlabInSecondBuddy =
            allocator.TryAllocateMemory(kSlabSize, 1, false, false, false);
        ASSERT_NE(firstSlabInSecondBuddy, nullptr);
        EXPECT_EQ(firstSlabInSecondBuddy->GetOffset(), 0u);
        EXPECT_EQ(firstSlabInSecondBuddy->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(firstSlabInSecondBuddy->GetSize(), kSlabSize);

        std::unique_ptr<MemoryAllocation> secondSlabInSecondBuddy =
            allocator.TryAllocateMemory(kSlabSize, 1, false, false, false);
        ASSERT_NE(secondSlabInSecondBuddy, nullptr);
        EXPECT_EQ(secondSlabInSecondBuddy->GetOffset(), kSlabSize);
        EXPECT_EQ(secondSlabInSecondBuddy->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(secondSlabInSecondBuddy->GetSize(), kSlabSize);

        // Free slab in second buddy.
        allocator.DeallocateMemory(std::move(secondSlabInSecondBuddy));
        allocator.DeallocateMemory(std::move(firstSlabInSecondBuddy));

        // Free slabs in first buddy.
        for (auto& allocation : allocations) {
            allocator.DeallocateMemory(std::move(allocation));
        }
    }
}

TEST(SlabCacheAllocatorTests, GetInfo) {
    // Test Slab allocator.
    {
        constexpr uint64_t kMinBlockSize = 4;
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                     kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                     kDefaultPrefetchSlab,
                                     std::make_unique<DummyMemoryAllocator>());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        EXPECT_NE(allocation, nullptr);

        // Single sub-allocation within a slab should be allocated.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, kBlockSize);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, kDefaultSlabSize);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, 0u);

        allocator.DeallocateMemory(std::move(allocation));

        // Both the sub-allocation and slab should be released.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, 0u);
    }

    // Test Slab + pooled allocator.
    {
        LIFOMemoryPool pool(kDefaultSlabSize);
        constexpr uint64_t kMinBlockSize = 4;
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                     kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                     kDefaultPrefetchSlab,
                                     std::make_unique<PooledMemoryAllocator>(
                                         std::make_unique<DummyMemoryAllocator>(), &pool));

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kBlockSize, 1, false, false, false);
        EXPECT_NE(allocation, nullptr);

        // Single sub-allocation within a slab should be used.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, kBlockSize);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, kDefaultSlabSize);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, 0u);

        allocator.DeallocateMemory(std::move(allocation));

        // Only the sub-allocation should be released.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, kDefaultSlabSize);
    }

    // Test Slab-Buddy allocator.
    {
        constexpr uint64_t kMaxBlockSize = 256;
        constexpr uint64_t kMinBlockSize = 4;
        constexpr uint64_t kMaxSlabSize = kMaxBlockSize;
        constexpr uint64_t kSlabSize = kDefaultSlabSize / 8;
        SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                     kDefaultSlabFragmentationLimit, kDefaultPrefetchSlab,
                                     std::make_unique<BuddyMemoryAllocator>(
                                         kMaxBlockSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                         std::make_unique<DummyMemoryAllocator>()));

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kMinBlockSize, 1, false, false, false);
        EXPECT_NE(allocation, nullptr);

        // Single slab block within buddy memory should be used.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, kMinBlockSize);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, kDefaultSlabSize);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, 0u);

        allocator.DeallocateMemory(std::move(allocation));

        // Both the slab block and buddy memory should be released.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
        EXPECT_EQ(allocator.GetInfo().FreeMemoryUsage, 0u);
    }
}

// Pre-fetch |kNumOfSlabs| slabs worth of sub-allocations of various sizes.
TEST(SlabCacheAllocatorTests, PrefetchSlabs) {
    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMinBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = 512;

    SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                 kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                 /*prefetchSlab*/ true, std::make_unique<DummyMemoryAllocator>());

    constexpr uint64_t kNumOfSlabs = 10u;
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
    for (size_t i = 0; i < kNumOfSlabs * (kDefaultSlabSize / kBlockSize); i++) {
        allocations.push_back(allocator.TryAllocateMemory(kBlockSize, 1, false, false, false));
        allocations.push_back(allocator.TryAllocateMemory(kBlockSize * 2, 1, false, false, false));
        allocations.push_back(allocator.TryAllocateMemory(kBlockSize * 3, 1, false, false, false));
    }

    for (auto& allocation : allocations) {
        allocator.DeallocateMemory(std::move(allocation));
    }
}
