// Copyright 2019 The Dawn Authors
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
#include "tests/DummyMemoryAllocator.h"

#include <set>
#include <vector>

using namespace gpgmm;

static constexpr uint64_t kDefaultMemorySize = 128u;
static constexpr uint64_t kDefaultMemoryAlignment = 1u;

class BuddyMemoryAllocatorTests : public testing::Test {
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

// Verify a single resource allocation in a single heap.
TEST_F(BuddyMemoryAllocatorTests, SingleHeap) {
    // After one 128 byte resource allocation:
    //
    // max block size -> ---------------------------
    //                   |          A1/H0          |       Hi - Heap at index i
    // max heap size  -> ---------------------------       An - Resource allocation n
    //
    constexpr uint64_t maxBlockSize = kDefaultMemorySize;
    BuddyMemoryAllocator allocator(maxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    // Cannot allocate greater than heap size.
    {
        std::unique_ptr<MemoryAllocation> invalidAllocation = allocator.TryAllocateMemory(
            CreateBasicRequest(kDefaultMemorySize * 2, kDefaultMemoryAlignment));
        ASSERT_EQ(invalidAllocation, nullptr);
    }

    // Allocate one 128 byte allocation (same size as heap).
    std::unique_ptr<MemoryAllocation> allocation1 =
        allocator.TryAllocateMemory(CreateBasicRequest(128, kDefaultMemoryAlignment));
    ASSERT_NE(allocation1, nullptr);
    ASSERT_EQ(allocation1->GetBlock()->Offset, 0u);
    ASSERT_EQ(allocation1->GetMethod(), AllocationMethod::kSubAllocated);
    ASSERT_EQ(allocation1->GetSize(), 128u);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);

    // Cannot allocate when allocator is full.
    {
        std::unique_ptr<MemoryAllocation> invalidAllocation =
            allocator.TryAllocateMemory(CreateBasicRequest(128, kDefaultMemoryAlignment));
        ASSERT_EQ(invalidAllocation, nullptr);
    }

    allocator.DeallocateMemory(std::move(allocation1));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
}

// Verify that multiple allocation are created in separate heaps.
TEST_F(BuddyMemoryAllocatorTests, MultipleHeaps) {
    // After two 128 byte resource allocations:
    //
    // max block size -> ---------------------------
    //                   |                         |       Hi - Heap at index i
    // max heap size  -> ---------------------------       An - Resource allocation n
    //                   |   A1/H0    |    A2/H1   |
    //                   ---------------------------
    //
    constexpr uint64_t maxBlockSize = 256;
    BuddyMemoryAllocator allocator(maxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    // Cannot allocate greater than heap size.
    {
        std::unique_ptr<MemoryAllocation> invalidAllocation = allocator.TryAllocateMemory(
            CreateBasicRequest(kDefaultMemorySize * 2, kDefaultMemoryAlignment));
        ASSERT_EQ(invalidAllocation, nullptr);
    }

    // Cannot allocate greater than max block size.
    {
        std::unique_ptr<MemoryAllocation> invalidAllocation = allocator.TryAllocateMemory(
            CreateBasicRequest(maxBlockSize * 2, kDefaultMemoryAlignment));
        ASSERT_EQ(invalidAllocation, nullptr);
    }

    // Allocate two 128 byte allocations.
    std::unique_ptr<MemoryAllocation> allocation1 = allocator.TryAllocateMemory(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(allocation1, nullptr);
    ASSERT_EQ(allocation1->GetSize(), kDefaultMemorySize);
    ASSERT_EQ(allocation1->GetBlock()->Offset, 0u);
    ASSERT_EQ(allocation1->GetMethod(), AllocationMethod::kSubAllocated);

    // First allocation creates first heap.
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);

    std::unique_ptr<MemoryAllocation> allocation2 = allocator.TryAllocateMemory(
        CreateBasicRequest(kDefaultMemorySize, kDefaultMemoryAlignment));
    ASSERT_NE(allocation2, nullptr);
    ASSERT_EQ(allocation2->GetSize(), kDefaultMemorySize);
    ASSERT_EQ(allocation2->GetBlock()->Offset, kDefaultMemorySize);
    ASSERT_EQ(allocation2->GetMethod(), AllocationMethod::kSubAllocated);

    // Second allocation creates second heap.
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);
    ASSERT_NE(allocation1->GetMemory(), allocation2->GetMemory());

    // Deallocate both allocations
    allocator.DeallocateMemory(std::move(allocation1));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);  // Released H0

    allocator.DeallocateMemory(std::move(allocation2));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);  // Released H1
}

// Verify multiple sub-allocations can re-use heaps.
TEST_F(BuddyMemoryAllocatorTests, MultipleSplitHeaps) {
    // After two 64 byte allocations with 128 byte heaps.
    //
    // max block size -> ---------------------------
    //                   |                         |       Hi - Heap at index i
    // max heap size  -> ---------------------------       An - Resource allocation n
    //                   |     H0     |     H1     |
    //                   ---------------------------
    //                   |  A1 |  A2  |  A3 |      |
    //                   ---------------------------
    //
    constexpr uint64_t maxBlockSize = 256;
    BuddyMemoryAllocator allocator(maxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    // Allocate two 64 byte sub-allocations.
    std::unique_ptr<MemoryAllocation> allocation1 = allocator.TryAllocateMemory(
        CreateBasicRequest(kDefaultMemorySize / 2, kDefaultMemoryAlignment));
    ASSERT_NE(allocation1, nullptr);
    ASSERT_EQ(allocation1->GetSize(), kDefaultMemorySize / 2);
    ASSERT_EQ(allocation1->GetBlock()->Offset, 0u);
    ASSERT_EQ(allocation1->GetMethod(), AllocationMethod::kSubAllocated);

    // First sub-allocation creates first heap.
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);

    std::unique_ptr<MemoryAllocation> allocation2 = allocator.TryAllocateMemory(
        CreateBasicRequest(kDefaultMemorySize / 2, kDefaultMemoryAlignment));
    ASSERT_NE(allocation2, nullptr);
    ASSERT_EQ(allocation2->GetSize(), kDefaultMemorySize / 2);
    ASSERT_EQ(allocation2->GetBlock()->Offset, kDefaultMemorySize / 2);
    ASSERT_EQ(allocation2->GetMethod(), AllocationMethod::kSubAllocated);

    // Second allocation re-uses first heap.
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);
    ASSERT_EQ(allocation1->GetMemory(), allocation2->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation3 = allocator.TryAllocateMemory(
        CreateBasicRequest(kDefaultMemorySize / 2, kDefaultMemoryAlignment));
    ASSERT_NE(allocation3, nullptr);
    ASSERT_EQ(allocation3->GetSize(), kDefaultMemorySize / 2);
    ASSERT_EQ(allocation3->GetBlock()->Offset, kDefaultMemorySize);
    ASSERT_EQ(allocation3->GetMethod(), AllocationMethod::kSubAllocated);

    // Third allocation creates second heap.
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);
    ASSERT_NE(allocation1->GetMemory(), allocation3->GetMemory());

    // Deallocate all allocations in reverse order.
    allocator.DeallocateMemory(std::move(allocation1));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount,
              2u);  // A2 pins H0.

    allocator.DeallocateMemory(std::move(allocation2));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);  // Released H0

    allocator.DeallocateMemory(std::move(allocation3));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);  // Released H1
}

// Verify resource sub-allocation of various sizes over multiple heaps.
TEST_F(BuddyMemoryAllocatorTests, MultiplSplitHeapsVariableSizes) {
    // After three 64 byte allocations and two 128 byte allocations.
    //
    // max block size -> -------------------------------------------------------
    //                   |                                                     |
    //                   -------------------------------------------------------
    //                   |                         |                           |
    // max heap size  -> -------------------------------------------------------
    //                   |     H0     |    A3/H1   |      H2     |    A5/H3    |
    //                   -------------------------------------------------------
    //                   |  A1 |  A2  |            |   A4  |     |             |
    //                   -------------------------------------------------------
    //
    constexpr uint64_t maxBlockSize = 512;
    BuddyMemoryAllocator allocator(maxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    // Allocate two 64-byte allocations.
    std::unique_ptr<MemoryAllocation> allocation1 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, kDefaultMemoryAlignment));
    ASSERT_NE(allocation1, nullptr);
    ASSERT_EQ(allocation1->GetSize(), 64u);
    ASSERT_EQ(allocation1->GetBlock()->Offset, 0u);
    ASSERT_EQ(allocation1->GetOffset(), 0u);
    ASSERT_EQ(allocation1->GetMethod(), AllocationMethod::kSubAllocated);

    std::unique_ptr<MemoryAllocation> allocation2 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, kDefaultMemoryAlignment));
    ASSERT_NE(allocation2, nullptr);
    ASSERT_EQ(allocation2->GetSize(), 64u);
    ASSERT_EQ(allocation2->GetBlock()->Offset, 64u);
    ASSERT_EQ(allocation2->GetOffset(), 64u);
    ASSERT_EQ(allocation2->GetMethod(), AllocationMethod::kSubAllocated);

    // A1 and A2 share H0
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);
    ASSERT_EQ(allocation1->GetMemory(), allocation2->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation3 =
        allocator.TryAllocateMemory(CreateBasicRequest(128, kDefaultMemoryAlignment));
    ASSERT_NE(allocation3, nullptr);
    ASSERT_EQ(allocation3->GetSize(), 128u);
    ASSERT_EQ(allocation3->GetBlock()->Offset, 128u);
    ASSERT_EQ(allocation3->GetOffset(), 0u);
    ASSERT_EQ(allocation3->GetMethod(), AllocationMethod::kSubAllocated);

    // A3 creates and fully occupies a new heap.
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);
    ASSERT_NE(allocation2->GetMemory(), allocation3->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation4 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, kDefaultMemoryAlignment));
    ASSERT_NE(allocation4, nullptr);
    ASSERT_EQ(allocation4->GetSize(), 64u);
    ASSERT_EQ(allocation4->GetBlock()->Offset, 256u);
    ASSERT_EQ(allocation4->GetOffset(), 0u);
    ASSERT_EQ(allocation4->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 3u);
    ASSERT_NE(allocation3->GetMemory(), allocation4->GetMemory());

    // R5 size forms 64 byte hole after R4.
    std::unique_ptr<MemoryAllocation> allocation5 =
        allocator.TryAllocateMemory(CreateBasicRequest(128, kDefaultMemoryAlignment));
    ASSERT_NE(allocation5, nullptr);
    ASSERT_EQ(allocation5->GetSize(), 128u);
    ASSERT_EQ(allocation5->GetBlock()->Offset, 384u);
    ASSERT_EQ(allocation5->GetOffset(), 0u);
    ASSERT_EQ(allocation5->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 4u);
    ASSERT_NE(allocation4->GetMemory(), allocation5->GetMemory());

    // Deallocate allocations in staggered order.
    allocator.DeallocateMemory(std::move(allocation1));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 4u);  // A2 pins H0

    allocator.DeallocateMemory(std::move(allocation5));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 3u);  // Released H3

    allocator.DeallocateMemory(std::move(allocation2));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);  // Released H0

    allocator.DeallocateMemory(std::move(allocation4));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);  // Released H2

    allocator.DeallocateMemory(std::move(allocation3));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);  // Released H1
}

// Verify resource sub-allocation of same sizes with various alignments.
TEST_F(BuddyMemoryAllocatorTests, SameSizeVariousAlignment) {
    // After three 64 byte and one 128 byte resource allocations.
    //
    // max block size -> -------------------------------------------------------
    //                   |                                                     |
    //                   -------------------------------------------------------
    //                   |                         |                           |
    // max heap size  -> -------------------------------------------------------
    //                   |     H0     |     H1     |     H2     |              |
    //                   -------------------------------------------------------
    //                   |  A1  |     |  A2  |     |  A3  |  A4 |              |
    //                   -------------------------------------------------------
    //
    constexpr uint64_t maxBlockSize = 512;
    BuddyMemoryAllocator allocator(maxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    std::unique_ptr<MemoryAllocation> allocation1 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, 128));
    ASSERT_NE(allocation1, nullptr);
    ASSERT_EQ(allocation1->GetSize(), 64u);
    ASSERT_EQ(allocation1->GetBlock()->Offset, 0u);
    ASSERT_EQ(allocation1->GetOffset(), 0u);
    ASSERT_EQ(allocation1->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);

    std::unique_ptr<MemoryAllocation> allocation2 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, 128));
    ASSERT_NE(allocation2, nullptr);
    ASSERT_EQ(allocation2->GetSize(), 64u);
    ASSERT_EQ(allocation2->GetBlock()->Offset, 128u);
    ASSERT_EQ(allocation2->GetOffset(), 0u);
    ASSERT_EQ(allocation2->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);
    ASSERT_NE(allocation1->GetMemory(), allocation2->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation3 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, 128));
    ASSERT_NE(allocation3, nullptr);
    ASSERT_EQ(allocation3->GetSize(), 64u);
    ASSERT_EQ(allocation3->GetBlock()->Offset, 256u);
    ASSERT_EQ(allocation3->GetOffset(), 0u);
    ASSERT_EQ(allocation3->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 3u);
    ASSERT_NE(allocation2->GetMemory(), allocation3->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation4 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, 64));
    ASSERT_NE(allocation4, nullptr);
    ASSERT_EQ(allocation4->GetSize(), 64u);
    ASSERT_EQ(allocation4->GetBlock()->Offset, 320u);
    ASSERT_EQ(allocation4->GetOffset(), 64u);
    ASSERT_EQ(allocation4->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 3u);
    ASSERT_EQ(allocation3->GetMemory(), allocation4->GetMemory());

    allocator.DeallocateMemory(std::move(allocation1));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);

    allocator.DeallocateMemory(std::move(allocation2));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);

    allocator.DeallocateMemory(std::move(allocation3));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);

    allocator.DeallocateMemory(std::move(allocation4));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
}

// Verify resource sub-allocation of various sizes with same alignments.
TEST_F(BuddyMemoryAllocatorTests, VariousSizeSameAlignment) {
    // After two 64 byte and two 128 byte resource allocations:
    //
    // max block size -> -------------------------------------------------------
    //                   |                                                     |
    //                   -------------------------------------------------------
    //                   |                         |                           |
    // max heap size  -> -------------------------------------------------------
    //                   |     H0     |    A3/H1   |    A4/H2   |              |
    //                   -------------------------------------------------------
    //                   |  A1 |  A2  |            |            |              |
    //                   -------------------------------------------------------
    //
    constexpr uint64_t maxBlockSize = 512;
    BuddyMemoryAllocator allocator(maxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    constexpr uint64_t alignment = 64;

    std::unique_ptr<MemoryAllocation> allocation1 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, alignment));
    ASSERT_NE(allocation1, nullptr);
    ASSERT_EQ(allocation1->GetSize(), 64u);
    ASSERT_EQ(allocation1->GetBlock()->Offset, 0u);
    ASSERT_EQ(allocation1->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);

    std::unique_ptr<MemoryAllocation> allocation2 =
        allocator.TryAllocateMemory(CreateBasicRequest(64, alignment));
    ASSERT_NE(allocation2, nullptr);
    ASSERT_EQ(allocation2->GetSize(), 64u);
    ASSERT_EQ(allocation2->GetBlock()->Offset, 64u);
    ASSERT_EQ(allocation2->GetOffset(), 64u);
    ASSERT_EQ(allocation2->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);  // Reuses H0
    ASSERT_EQ(allocation1->GetMemory(), allocation2->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation3 =
        allocator.TryAllocateMemory(CreateBasicRequest(128, alignment));
    ASSERT_NE(allocation3, nullptr);
    ASSERT_EQ(allocation3->GetSize(), 128u);
    ASSERT_EQ(allocation3->GetBlock()->Offset, 128u);
    ASSERT_EQ(allocation3->GetOffset(), 0u);
    ASSERT_EQ(allocation3->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);
    ASSERT_NE(allocation2->GetMemory(), allocation3->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation4 =
        allocator.TryAllocateMemory(CreateBasicRequest(128, alignment));
    ASSERT_NE(allocation4, nullptr);
    ASSERT_EQ(allocation4->GetSize(), 128u);
    ASSERT_EQ(allocation4->GetBlock()->Offset, 256u);
    ASSERT_EQ(allocation4->GetOffset(), 0u);
    ASSERT_EQ(allocation4->GetMethod(), AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 3u);
    ASSERT_NE(allocation3->GetMemory(), allocation4->GetMemory());

    allocator.DeallocateMemory(std::move(allocation1));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 3u);

    allocator.DeallocateMemory(std::move(allocation2));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 2u);

    allocator.DeallocateMemory(std::move(allocation3));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 1u);

    allocator.DeallocateMemory(std::move(allocation4));
    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);
}

// Verify allocating a very large resource does not overflow.
TEST_F(BuddyMemoryAllocatorTests, AllocationOverflow) {
    constexpr uint64_t maxBlockSize = 512;
    BuddyMemoryAllocator allocator(maxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::make_unique<DummyMemoryAllocator>());

    constexpr uint64_t largeBlock = (1ull << 63) + 1;
    std::unique_ptr<MemoryAllocation> invalidAllocation =
        allocator.TryAllocateMemory(CreateBasicRequest(largeBlock, kDefaultMemoryAlignment));
    ASSERT_EQ(invalidAllocation, nullptr);
}

// Verify resource heaps will be reused from a pool.
TEST_F(BuddyMemoryAllocatorTests, ReuseFreedHeaps) {
    constexpr uint64_t kMaxBlockSize = 4096;

    LIFOMemoryPool pool(kDefaultMemorySize);
    std::unique_ptr<PooledMemoryAllocator> poolAllocator =
        std::make_unique<PooledMemoryAllocator>(std::make_unique<DummyMemoryAllocator>(), &pool);

    BuddyMemoryAllocator allocator(kMaxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::move(poolAllocator));

    std::set<MemoryBase*> heaps = {};
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};

    constexpr uint32_t kNumOfAllocations = 100;

    // Allocate |kNumOfAllocations|.
    for (uint32_t i = 0; i < kNumOfAllocations; i++) {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(4, kDefaultMemoryAlignment));
        ASSERT_NE(allocation, nullptr);
        ASSERT_EQ(allocation->GetSize(), 4u);
        ASSERT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        heaps.insert(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    ASSERT_EQ(pool.GetPoolSize(), 0u);

    // Return the allocations to the pool.
    for (auto& allocation : allocations) {
        ASSERT_NE(allocation, nullptr);
        allocator.DeallocateMemory(std::move(allocation));
    }

    ASSERT_EQ(pool.GetPoolSize(), heaps.size());

    allocations.clear();

    // Allocate again reusing the same heaps.
    for (uint32_t i = 0; i < kNumOfAllocations; i++) {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(4, kDefaultMemoryAlignment));
        ASSERT_NE(allocation, nullptr);
        ASSERT_EQ(allocation->GetSize(), 4u);
        ASSERT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        ASSERT_FALSE(heaps.insert(allocation->GetMemory()).second);
        allocations.push_back(std::move(allocation));
    }

    ASSERT_EQ(pool.GetPoolSize(), 0u);

    for (auto& allocation : allocations) {
        ASSERT_NE(allocation, nullptr);
        allocator.DeallocateMemory(std::move(allocation));
    }

    ASSERT_EQ(allocator.GetInfo().UsedMemoryCount, 0u);

    pool.ReleasePool();
}

// Verify resource heaps that were reused from a pool can be destroyed.
TEST_F(BuddyMemoryAllocatorTests, DestroyHeaps) {
    constexpr uint64_t kMaxBlockSize = 4096;

    LIFOMemoryPool pool(kDefaultMemorySize);
    std::unique_ptr<PooledMemoryAllocator> poolAllocator =
        std::make_unique<PooledMemoryAllocator>(std::make_unique<DummyMemoryAllocator>(), &pool);
    BuddyMemoryAllocator allocator(kMaxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
                                   std::move(poolAllocator));

    std::set<MemoryBase*> heaps = {};
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};

    // Count by heap (vs number of allocations) to ensure there are exactly |kNumOfHeaps| worth of
    // buffers. Otherwise, the heap may be reused if not full.
    constexpr uint32_t kNumOfHeaps = 10;

    // Allocate |kNumOfHeaps| worth.
    while (heaps.size() < kNumOfHeaps) {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(CreateBasicRequest(4, kDefaultMemoryAlignment));
        ASSERT_NE(allocation, nullptr);
        ASSERT_EQ(allocation->GetSize(), 4u);
        ASSERT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        heaps.insert(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    ASSERT_EQ(pool.GetPoolSize(), 0u);

    // Return the allocations to the pool.
    for (auto& allocation : allocations) {
        ASSERT_NE(allocation, nullptr);
        allocator.DeallocateMemory(std::move(allocation));
    }

    ASSERT_EQ(pool.GetPoolSize(), kNumOfHeaps);

    pool.ReleasePool();
}
