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

#include "gpgmm/common/BuddyMemoryAllocator.h"
#include "gpgmm/common/LIFOMemoryPool.h"
#include "gpgmm/common/PooledMemoryAllocator.h"
#include "gpgmm/common/SlabMemoryAllocator.h"
#include "gpgmm/utils/Math.h"
#include "tests/DummyMemoryAllocator.h"

#include <set>
#include <vector>

using namespace gpgmm;

static constexpr uint64_t kDefaultSlabSize = 128u;
static constexpr uint64_t kDefaultSlabAlignment = 1u;
static constexpr double kDefaultSlabFragmentationLimit = 0.125;
static constexpr double kNoSlabGrowthFactor = 1.0;
static constexpr bool kNoSlabPrefetchAllowed = false;

class SlabMemoryAllocatorTests : public testing::Test {
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

// Verify allocation in a single slab.
TEST_F(SlabMemoryAllocatorTests, SingleSlab) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    // Verify allocation greater then the block size fails.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
                                      dummyMemoryAllocator.get());

        ASSERT_EQ(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize * 2, 1)), nullptr);
    }

    // Verify allocation greater then slab size fails.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
                                      dummyMemoryAllocator.get());

        ASSERT_EQ(allocator.TryAllocateMemory(CreateBasicRequest(kMaxSlabSize, 1)), nullptr);
        ASSERT_EQ(allocator.TryAllocateMemory(CreateBasicRequest(kMaxSlabSize - 1, 1)), nullptr);
    }

    // Verify allocation equal to the slab size always succeeds.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
        constexpr uint64_t kMaxSlabSize = kBlockSize;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                      kNoSlabGrowthFactor, dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kBlockSize);

        allocator.DeallocateMemory(std::move(allocation));
    }

    // Verify allocation cannot exceed the fragmentation threshold.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kMaxSlabSize = 32;
        constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                      kNoSlabGrowthFactor, dummyMemoryAllocator.get());

        // Max allocation cannot be more than 1/8th the max slab size or 4 bytes.
        // Since a 10 byte allocation requires a 128 byte slab, allocation should always fail.
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(10, 1));
        ASSERT_EQ(allocation, nullptr);

        // Re-attempt with an allocation that is under the fragmentation limit.
        allocation = allocator.TryAllocateMemory(CreateBasicRequest(14, 1));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kBlockSize);

        allocator.DeallocateMemory(std::move(allocation));
    }

    // Verify allocation succeeds when specifying a slab size.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kSlabSize = 32;
        constexpr uint64_t kMaxSlabSize = 128;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                      kNoSlabGrowthFactor, dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocation, nullptr);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
        EXPECT_GE(allocation->GetMemory()->GetSize(), kSlabSize);

        allocator.DeallocateMemory(std::move(allocation));
    }

    // Verify allocation succeeds when specifying a NPOT slab size.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kSlabSize = 33;
        constexpr uint64_t kMaxSlabSize = 128;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                      kNoSlabGrowthFactor, dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocation, nullptr);
        EXPECT_GE(allocation->GetSize(), kBlockSize);
        EXPECT_GE(allocation->GetMemory()->GetSize(), kSlabSize);

        allocator.DeallocateMemory(std::move(allocation));
    }

    // Verify requesting an allocation without memory will not return a valid allocation.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
                                      dummyMemoryAllocator.get());

        EXPECT_EQ(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1, true)), nullptr);
        EXPECT_EQ(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize / 2, 1, true)),
                  nullptr);
        EXPECT_EQ(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize / 4, 1, true)),
                  nullptr);
    }
}

// Verify allocation in multiple slabs.
TEST_F(SlabMemoryAllocatorTests, MultipleSlabs) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    // Fill up exactly N slabs (allocation = block = slab size).
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;

        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, /*slabSize*/ kBlockSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
                                      dummyMemoryAllocator.get());
        const uint64_t kNumOfSlabs = 12;
        std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
        for (uint32_t slabi = 0; slabi < kNumOfSlabs; slabi++) {
            std::unique_ptr<MemoryAllocation> allocation =
                allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
            ASSERT_NE(allocation, nullptr);
            allocations.push_back(std::move(allocation));
        }

        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, kNumOfSlabs);

        for (auto& allocation : allocations) {
            allocator.DeallocateMemory(std::move(allocation));
        }

        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
    }

    // Fill up slabs through pre-allocation (allocation < block < slab size).
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;

        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
                                      dummyMemoryAllocator.get());
        // Fill up exactly two 128B slabs.
        std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
        for (uint32_t blocki = 0; blocki < (kDefaultSlabSize * 2 / kBlockSize); blocki++) {
            std::unique_ptr<MemoryAllocation> allocation =
                allocator.TryAllocateMemory(CreateBasicRequest(22, 1));
            ASSERT_NE(allocation, nullptr);
            allocations.push_back(std::move(allocation));
        }

        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);

        // Free both slabs.
        for (auto& allocation : allocations) {
            allocator.DeallocateMemory(std::move(allocation));
        }

        EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
    }

    // Verify slabs are reused in LIFO.
    {
        constexpr uint64_t kBlockSize = 64;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
                                      dummyMemoryAllocator.get());

        // Both allocation A and B go in Slab A, which will become full.
        std::unique_ptr<MemoryAllocation> allocationAinSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationAinSlabA, nullptr);

        std::unique_ptr<MemoryAllocation> allocationBInSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationAinSlabA, nullptr);

        EXPECT_EQ(allocationAinSlabA->GetMemory(), allocationBInSlabA->GetMemory());

        // Allocation C and D go in Slab B, which will become full.
        std::unique_ptr<MemoryAllocation> allocationCInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationCInSlabB, nullptr);

        EXPECT_NE(allocationBInSlabA->GetMemory(), allocationCInSlabB->GetMemory());

        std::unique_ptr<MemoryAllocation> allocationDInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationDInSlabB, nullptr);

        EXPECT_EQ(allocationCInSlabB->GetMemory(), allocationDInSlabB->GetMemory());

        // Allocation E and F goes in Slab C, which will become full.
        std::unique_ptr<MemoryAllocation> allocationEInSlabC =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationEInSlabC, nullptr);

        EXPECT_NE(allocationDInSlabB->GetMemory(), allocationEInSlabC->GetMemory());

        std::unique_ptr<MemoryAllocation> allocationFInSlabC =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationFInSlabC, nullptr);

        EXPECT_EQ(allocationEInSlabC->GetMemory(), allocationFInSlabC->GetMemory());

        // Free list: []
        // Full list: C -> B -> A.

        allocator.DeallocateMemory(std::move(allocationAinSlabA));
        allocator.DeallocateMemory(std::move(allocationCInSlabB));

        // Free list: B -> A.
        // Full list: C.

        std::unique_ptr<MemoryAllocation> allocationGInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationGInSlabB, nullptr);
        EXPECT_EQ(allocationDInSlabB->GetMemory(), allocationGInSlabB->GetMemory());

        // Free list: A.
        // Full list: B -> C.

        std::unique_ptr<MemoryAllocation> allocationHInSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
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
TEST_F(SlabMemoryAllocatorTests, AllocationOverflow) {
    std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
        std::make_unique<DummyMemoryAllocator>();

    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMaxSlabSize = 512;
    SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                  kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                  kNoSlabGrowthFactor, dummyMemoryAllocator.get());

    constexpr uint64_t largeBlock = (1ull << 63) + 1;
    std::unique_ptr<MemoryAllocation> invalidAllocation =
        allocator.TryAllocateMemory(CreateBasicRequest(largeBlock, kDefaultSlabAlignment, true));
    ASSERT_EQ(invalidAllocation, nullptr);
}

// Verify slab will be reused from a pool.
TEST_F(SlabMemoryAllocatorTests, ReuseSlabs) {
    std::unique_ptr<PooledMemoryAllocator> poolAllocator = std::make_unique<PooledMemoryAllocator>(
        kDefaultSlabSize, kDefaultSlabAlignment, std::make_unique<DummyMemoryAllocator>());

    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMaxSlabSize = 512;
    SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                  kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                  kNoSlabGrowthFactor, poolAllocator.get());

    std::set<MemoryBase*> slabMemory = {};
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};

    // Count by slabs (vs number of allocations) to ensure there are exactly |kNumOfSlabs| worth of
    // allocations. Otherwise, the slab may be reused if not full.
    constexpr uint32_t kNumOfSlabs = 10;

    // Allocate |kNumOfSlabs| worth.
    while (slabMemory.size() < kNumOfSlabs) {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(), kBlockSize);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        slabMemory.insert(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    EXPECT_EQ(poolAllocator->GetInfo().FreeMemoryUsage, 0u);

    // Return the allocations to the pool.
    for (auto& allocation : allocations) {
        ASSERT_NE(allocation, nullptr);
        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(poolAllocator->GetInfo().FreeMemoryUsage, kDefaultSlabSize * kNumOfSlabs);

    poolAllocator->ReleaseMemory();
}

TEST_F(SlabMemoryAllocatorTests, GetInfo) {
    // Test slab allocator.
    {
        std::unique_ptr<DummyMemoryAllocator> dummyMemoryAllocator =
            std::make_unique<DummyMemoryAllocator>();

        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
                                      dummyMemoryAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
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
        std::unique_ptr<PooledMemoryAllocator> poolAllocator =
            std::make_unique<PooledMemoryAllocator>(kDefaultSlabSize, kDefaultSlabAlignment,
                                                    std::make_unique<DummyMemoryAllocator>());

        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kDefaultSlabSize,
                                      kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
                                      kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
                                      poolAllocator.get());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
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

// Grow slabs one after another below kMaxSlabSize.
TEST_F(SlabMemoryAllocatorTests, SlabGrowth) {
    // Start from kMinSlabSize == kBlockSize.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        constexpr uint64_t kMinSlabSize = kBlockSize;

        DummyMemoryAllocator dummyAllocator;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kMinSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, false,
                                      /*slabGrowthFactor*/ 2, &dummyAllocator);

        // Slab A holds 1 allocation.
        std::unique_ptr<MemoryAllocation> allocationAInSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabA->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabA->GetMemory()->GetSize(), kBlockSize);

        // Slab B holds 1 allocation.
        std::unique_ptr<MemoryAllocation> allocationAInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabB->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabB->GetMemory()->GetSize(), kBlockSize);

        // Slab C grows 2x and holds 2 allocations per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabC =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabC->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabC->GetMemory()->GetSize(), kBlockSize * 2);

        std::unique_ptr<MemoryAllocation> allocationBInSlabC =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationBInSlabC->GetSize(), kBlockSize);
        EXPECT_EQ(allocationBInSlabC->GetMemory()->GetSize(), kBlockSize * 2);

        // Slab D still holds 2 allocations per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabD =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabD->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabD->GetMemory()->GetSize(), kBlockSize * 2);

        std::unique_ptr<MemoryAllocation> allocationBInSlabD =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationBInSlabD->GetSize(), kBlockSize);
        EXPECT_EQ(allocationBInSlabD->GetMemory()->GetSize(), kBlockSize * 2);

        allocator.DeallocateMemory(std::move(allocationBInSlabD));
        allocator.DeallocateMemory(std::move(allocationAInSlabD));
        allocator.DeallocateMemory(std::move(allocationBInSlabC));
        allocator.DeallocateMemory(std::move(allocationAInSlabC));
        allocator.DeallocateMemory(std::move(allocationAInSlabB));
        allocator.DeallocateMemory(std::move(allocationAInSlabA));

        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
    }

    // Start from a kMinSlabSize > kBlockSize.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kMinSlabSize = 32;
        constexpr uint64_t kMaxSlabSize = 64;

        DummyMemoryAllocator dummyAllocator;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kMinSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, false,
                                      /*slabGrowthFactor*/ 2, &dummyAllocator);

        // Slab A holds 2 allocations per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabA->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabA->GetMemory()->GetSize(), kMinSlabSize);

        std::unique_ptr<MemoryAllocation> allocationBInSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationBInSlabA->GetSize(), kBlockSize);
        EXPECT_EQ(allocationBInSlabA->GetMemory()->GetSize(), kMinSlabSize);

        EXPECT_EQ(allocationAInSlabA->GetMemory(), allocationBInSlabA->GetMemory());

        // Slab B holds 2 allocations per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabB->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabB->GetMemory()->GetSize(), kMinSlabSize);

        std::unique_ptr<MemoryAllocation> allocationBInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationBInSlabB->GetSize(), kBlockSize);
        EXPECT_EQ(allocationBInSlabB->GetMemory()->GetSize(), kMinSlabSize);

        EXPECT_EQ(allocationAInSlabB->GetMemory(), allocationBInSlabB->GetMemory());

        // Slab C grows 2x and holds 4 allocations per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabC =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabC->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabC->GetMemory()->GetSize(), kMinSlabSize * 2);

        EXPECT_NE(allocationBInSlabB->GetMemory(), allocationAInSlabC->GetMemory());

        allocator.DeallocateMemory(std::move(allocationAInSlabC));
        allocator.DeallocateMemory(std::move(allocationBInSlabB));
        allocator.DeallocateMemory(std::move(allocationAInSlabB));
        allocator.DeallocateMemory(std::move(allocationBInSlabA));
        allocator.DeallocateMemory(std::move(allocationAInSlabA));

        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
    }
}

// Grow slabs until kMaxSlabSize is reached.
TEST_F(SlabMemoryAllocatorTests, SlabGrowthLimit) {
    // Start from a kMinSlabSize > kBlockSize.
    {
        constexpr uint64_t kBlockSize = 16;
        constexpr uint64_t kMinSlabSize = 32;
        constexpr uint64_t kMaxSlabSize = 64;

        DummyMemoryAllocator dummyAllocator;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kMinSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, false,
                                      /*slabGrowthFactor*/ 2, &dummyAllocator);

        // Slab A holds 2 allocations per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabA->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabA->GetMemory()->GetSize(), kMinSlabSize);

        std::unique_ptr<MemoryAllocation> allocationBInSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationBInSlabA->GetSize(), kBlockSize);
        EXPECT_EQ(allocationBInSlabA->GetMemory()->GetSize(), kMinSlabSize);

        EXPECT_EQ(allocationAInSlabA->GetMemory(), allocationBInSlabA->GetMemory());

        // Slab B holds 2 allocations per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabB->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabB->GetMemory()->GetSize(), kMinSlabSize);

        std::unique_ptr<MemoryAllocation> allocationBInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationBInSlabB->GetSize(), kBlockSize);
        EXPECT_EQ(allocationBInSlabB->GetMemory()->GetSize(), kMinSlabSize);

        EXPECT_EQ(allocationAInSlabB->GetMemory(), allocationBInSlabB->GetMemory());

        // Slab C grows 2x and holds 4 allocations per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabC =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabC->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabC->GetMemory()->GetSize(), kMinSlabSize * 2);

        EXPECT_NE(allocationBInSlabB->GetMemory(), allocationAInSlabC->GetMemory());

        allocator.DeallocateMemory(std::move(allocationAInSlabC));
        allocator.DeallocateMemory(std::move(allocationBInSlabB));
        allocator.DeallocateMemory(std::move(allocationAInSlabB));
        allocator.DeallocateMemory(std::move(allocationBInSlabA));
        allocator.DeallocateMemory(std::move(allocationAInSlabA));
    }

    // Start from a kMinSlabSize == kBlockSize.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 64;
        constexpr uint64_t kMinSlabSize = kBlockSize;

        DummyMemoryAllocator dummyAllocator;
        SlabMemoryAllocator allocator(kBlockSize, kMaxSlabSize, kMinSlabSize, kDefaultSlabAlignment,
                                      kDefaultSlabFragmentationLimit, false,
                                      /*slabGrowthFactor*/ 2, &dummyAllocator);

        // Slab A holds 1 allocation per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_EQ(allocationAInSlabA->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabA->GetMemory()->GetSize(), kBlockSize);

        // Slab B holds 1 allocation per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationAInSlabB, nullptr);
        EXPECT_EQ(allocationAInSlabB->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabB->GetMemory()->GetSize(), kBlockSize);

        EXPECT_NE(allocationAInSlabA->GetMemory(), allocationAInSlabB->GetMemory());

        // Slab C grows 2x and holds 2 allocation per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabC =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationAInSlabC, nullptr);
        EXPECT_EQ(allocationAInSlabC->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabC->GetMemory()->GetSize(), kBlockSize * 2);

        EXPECT_NE(allocationAInSlabB->GetMemory(), allocationAInSlabC->GetMemory());

        std::unique_ptr<MemoryAllocation> allocationBInSlabC =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationBInSlabC, nullptr);
        EXPECT_EQ(allocationBInSlabC->GetSize(), kBlockSize);
        EXPECT_EQ(allocationBInSlabC->GetMemory()->GetSize(), kBlockSize * 2);

        // Slab C still holds 2 allocation per slab.
        std::unique_ptr<MemoryAllocation> allocationAInSlabD =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationAInSlabD, nullptr);
        EXPECT_EQ(allocationAInSlabD->GetSize(), kBlockSize);
        EXPECT_EQ(allocationAInSlabD->GetMemory()->GetSize(), kBlockSize * 2);

        EXPECT_NE(allocationBInSlabC->GetMemory(), allocationAInSlabD->GetMemory());

        std::unique_ptr<MemoryAllocation> allocationBInSlabD =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationBInSlabD, nullptr);
        EXPECT_EQ(allocationBInSlabD->GetSize(), kBlockSize);
        EXPECT_EQ(allocationBInSlabD->GetMemory()->GetSize(), kBlockSize * 2);

        EXPECT_EQ(allocationAInSlabD->GetMemory(), allocationBInSlabD->GetMemory());

        allocator.DeallocateMemory(std::move(allocationBInSlabD));
        allocator.DeallocateMemory(std::move(allocationAInSlabD));
        allocator.DeallocateMemory(std::move(allocationBInSlabC));
        allocator.DeallocateMemory(std::move(allocationAInSlabC));
        allocator.DeallocateMemory(std::move(allocationAInSlabB));
        allocator.DeallocateMemory(std::move(allocationAInSlabA));

        EXPECT_EQ(allocator.GetInfo().UsedMemoryUsage, 0u);
    }
}

class SlabCacheAllocatorTests : public SlabMemoryAllocatorTests {};

TEST_F(SlabCacheAllocatorTests, SingleSlabMultipleSize) {
    constexpr uint64_t kMaxSlabSize = 256;
    constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
    SlabCacheAllocator allocator(kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                 kNoSlabGrowthFactor, std::make_unique<DummyMemoryAllocator>());

    // Verify requesting an allocation without memory will not return a valid allocation.
    {
        constexpr uint64_t kBlockSize = 4;
        EXPECT_EQ(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1, true)), nullptr);
        EXPECT_EQ(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize * 2, 1, true)),
                  nullptr);
    }
}

TEST_F(SlabCacheAllocatorTests, SingleSlabMultipleAlignments) {
    constexpr uint64_t kMaxSlabSize = 256;
    constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
    SlabCacheAllocator allocator(kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                 kNoSlabGrowthFactor, std::make_unique<DummyMemoryAllocator>());

    // Verify requesting an allocation of same size using multiple alignment succeeds.
    {
        constexpr uint64_t kBlockSize = 4;
        std::unique_ptr<MemoryAllocation> allocationWithAlignmentA =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        ASSERT_NE(allocationWithAlignmentA, nullptr);
        EXPECT_EQ(allocationWithAlignmentA->GetSize(), AlignTo(kBlockSize, 1));

        std::unique_ptr<MemoryAllocation> allocationWithAlignmentB =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 16));
        ASSERT_NE(allocationWithAlignmentB, nullptr);
        EXPECT_EQ(allocationWithAlignmentB->GetSize(), AlignTo(kBlockSize, 16));

        allocator.DeallocateMemory(std::move(allocationWithAlignmentB));
        allocator.DeallocateMemory(std::move(allocationWithAlignmentA));
    }
}

TEST_F(SlabCacheAllocatorTests, MultipleSlabsSameSize) {
    constexpr uint64_t kMaxSlabSize = 256;
    constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
    SlabCacheAllocator allocator(kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                 kNoSlabGrowthFactor, std::make_unique<DummyMemoryAllocator>());

    std::unique_ptr<MemoryAllocation> firstAllocation =
        allocator.TryAllocateMemory(CreateBasicRequest(22, 1));
    ASSERT_NE(firstAllocation, nullptr);

    std::unique_ptr<MemoryAllocation> secondAllocation =
        allocator.TryAllocateMemory(CreateBasicRequest(22, 1));
    ASSERT_NE(secondAllocation, nullptr);

    allocator.DeallocateMemory(std::move(firstAllocation));
    allocator.DeallocateMemory(std::move(secondAllocation));

    std::unique_ptr<MemoryAllocation> thirdAllocation =
        allocator.TryAllocateMemory(CreateBasicRequest(44, 1));
    ASSERT_NE(thirdAllocation, nullptr);

    std::unique_ptr<MemoryAllocation> fourthAllocation =
        allocator.TryAllocateMemory(CreateBasicRequest(44, 1));
    ASSERT_NE(fourthAllocation, nullptr);

    allocator.DeallocateMemory(std::move(thirdAllocation));
    allocator.DeallocateMemory(std::move(fourthAllocation));
}

TEST_F(SlabCacheAllocatorTests, MultipleSlabsVariableSizes) {
    constexpr uint64_t kMaxSlabSize = 256;
    constexpr uint64_t kSlabSize = 0;  // deduce slab size from allocation size.
    SlabCacheAllocator allocator(kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                 kNoSlabGrowthFactor, std::make_unique<DummyMemoryAllocator>());
    {
        constexpr uint64_t allocationSize = 22;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(allocationSize, 1));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), allocationSize);

        allocator.DeallocateMemory(std::move(allocation));
    }
    {
        constexpr uint64_t allocationSize = 44;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(allocationSize, 1));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), allocationSize);

        allocator.DeallocateMemory(std::move(allocation));
    }
    {
        constexpr uint64_t allocationSize = 88;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(allocationSize, 1));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), allocationSize);

        allocator.DeallocateMemory(std::move(allocation));
    }

    EXPECT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
}

TEST_F(SlabCacheAllocatorTests, SingleSlabInBuddy) {
    // 1. Create a buddy allocator as the back-end allocator.
    // 2. Create a slab allocator as the front-end allocator.
    constexpr uint64_t kMaxBlockSize = 256;
    constexpr uint64_t kMaxSlabSize = kMaxBlockSize;
    constexpr uint64_t kSlabSize = kDefaultSlabSize / 8;
    SlabCacheAllocator allocator(kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                 kNoSlabGrowthFactor,
                                 std::make_unique<BuddyMemoryAllocator>(
                                     kMaxBlockSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                     std::make_unique<DummyMemoryAllocator>()));

    constexpr uint64_t kBlockSize = 4;
    std::unique_ptr<MemoryAllocation> allocation =
        allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetOffset(), 0u);
    EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
    EXPECT_GE(allocation->GetSize(), kBlockSize);

    allocator.DeallocateMemory(std::move(allocation));
}

TEST_F(SlabCacheAllocatorTests, MultipleSlabsInBuddy) {
    // 1. Create a buddy allocator as the back-end allocator.
    // 2. Create a slab allocator as the front-end allocator.
    constexpr uint64_t kMaxBlockSize = 256;
    constexpr uint64_t kMaxSlabSize = kMaxBlockSize;
    constexpr uint64_t kSlabSize = kDefaultSlabSize / 8;
    SlabCacheAllocator allocator(kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                 kNoSlabGrowthFactor,
                                 std::make_unique<BuddyMemoryAllocator>(
                                     kMaxBlockSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                     std::make_unique<DummyMemoryAllocator>()));

    // Verify multiple slab-buddy sub-allocation in the same slab are allocated contigiously.
    {
        constexpr uint64_t allocationSize = 8;
        std::unique_ptr<MemoryAllocation> firstAllocation =
            allocator.TryAllocateMemory(CreateBasicRequest(allocationSize, 1));
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetOffset(), 0u);
        EXPECT_EQ(firstAllocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(firstAllocation->GetSize(), allocationSize);

        EXPECT_EQ(firstAllocation->GetMemory()->GetSize(), kDefaultSlabSize);

        std::unique_ptr<MemoryAllocation> secondAllocation =
            allocator.TryAllocateMemory(CreateBasicRequest(allocationSize, 1));
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
                allocator.TryAllocateMemory(CreateBasicRequest(kSlabSize, 1));
            ASSERT_NE(allocation, nullptr);
            EXPECT_EQ(allocation->GetOffset(), i * kSlabSize);
            EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
            EXPECT_GE(allocation->GetSize(), kSlabSize);
            allocations.push_back(std::move(allocation));
        }

        // Next slab-buddy sub-allocation must be in the second buddy.
        std::unique_ptr<MemoryAllocation> firstSlabInSecondBuddy =
            allocator.TryAllocateMemory(CreateBasicRequest(kSlabSize, 1));
        ASSERT_NE(firstSlabInSecondBuddy, nullptr);
        EXPECT_EQ(firstSlabInSecondBuddy->GetOffset(), 0u);
        EXPECT_EQ(firstSlabInSecondBuddy->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(firstSlabInSecondBuddy->GetSize(), kSlabSize);

        std::unique_ptr<MemoryAllocation> secondSlabInSecondBuddy =
            allocator.TryAllocateMemory(CreateBasicRequest(kSlabSize, 1));
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

TEST_F(SlabCacheAllocatorTests, GetInfo) {
    // Test Slab allocator.
    {
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabCacheAllocator allocator(kMaxSlabSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                     kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                     kNoSlabGrowthFactor, std::make_unique<DummyMemoryAllocator>());

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
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
        constexpr uint64_t kBlockSize = 32;
        constexpr uint64_t kMaxSlabSize = 512;
        SlabCacheAllocator allocator(
            kMaxSlabSize, kDefaultSlabSize, kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
            kNoSlabPrefetchAllowed, kNoSlabGrowthFactor,
            std::make_unique<PooledMemoryAllocator>(kDefaultSlabSize, kDefaultSlabAlignment,
                                                    std::make_unique<DummyMemoryAllocator>()));

        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
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
        constexpr uint64_t kMaxSlabSize = kMaxBlockSize;
        constexpr uint64_t kSlabSize = kDefaultSlabSize / 8;
        SlabCacheAllocator allocator(kMaxSlabSize, kSlabSize, kDefaultSlabAlignment,
                                     kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                     kNoSlabGrowthFactor,
                                     std::make_unique<BuddyMemoryAllocator>(
                                         kMaxBlockSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                         std::make_unique<DummyMemoryAllocator>()));

        constexpr uint64_t kBlockSize = 4;
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1));
        EXPECT_NE(allocation, nullptr);

        // Single slab block within buddy memory should be used.
        EXPECT_EQ(allocator.GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(allocator.GetInfo().UsedBlockUsage, kBlockSize);
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
TEST_F(SlabCacheAllocatorTests, SlabPrefetch) {
    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kMaxSlabSize = 512;

    SlabCacheAllocator allocator(
        kMaxSlabSize, kDefaultSlabSize, kDefaultSlabAlignment, kDefaultSlabFragmentationLimit,
        /*prefetchSlab*/ true, kNoSlabGrowthFactor, std::make_unique<DummyMemoryAllocator>());

    constexpr uint64_t kNumOfSlabs = 10u;
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
    for (size_t i = 0; i < kNumOfSlabs * (kDefaultSlabSize / kBlockSize); i++) {
        allocations.push_back(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize, 1)));
        allocations.push_back(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize * 2, 1)));
        allocations.push_back(allocator.TryAllocateMemory(CreateBasicRequest(kBlockSize * 3, 1)));
    }

    for (auto& allocation : allocations) {
        allocator.DeallocateMemory(std::move(allocation));
    }
}

// Verify creating more slabs than memory available fails.
TEST_F(SlabCacheAllocatorTests, OutOfMemory) {
    SlabCacheAllocator allocator(kDefaultSlabSize, kDefaultSlabSize, kDefaultSlabAlignment,
                                 kDefaultSlabFragmentationLimit, kNoSlabPrefetchAllowed,
                                 kNoSlabGrowthFactor, std::make_unique<DummyMemoryAllocator>());

    constexpr uint64_t kTotalMemoryAvailable = 512;

    MemoryAllocationRequest request = CreateBasicRequest(32, 1);
    request.AvailableForAllocation = kTotalMemoryAvailable;

    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
    while (true) {
        std::unique_ptr<MemoryAllocation> allocation = allocator.TryAllocateMemory(request);
        if (allocation == nullptr) {
            break;
        }
        request.AvailableForAllocation =
            (kTotalMemoryAvailable - allocator.GetInfo().UsedMemoryUsage);
        allocations.push_back(std::move(allocation));
    }

    for (auto& allocation : allocations) {
        allocator.DeallocateMemory(std::move(allocation));
    }
}
