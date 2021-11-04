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

#include "src/LIFOPooledMemoryAllocator.h"
#include "src/Memory.h"
#include "src/VirtualBuddyMemoryAllocator.h"

#include <set>
#include <vector>

using namespace gpgmm;

static constexpr uint64_t kHeapSize = 128u;
static constexpr uint64_t kHeapAlignment = 1u;

class DummyMemoryAllocator : public MemoryAllocator {
  public:
    std::unique_ptr<MemoryAllocation> AllocateMemory(uint64_t size, uint64_t alignment) override {
        AllocationInfo info = {};
        info.mMethod = AllocationMethod::kStandalone;
        return std::make_unique<MemoryAllocation>(this, info, /*offset*/ 0, new MemoryBase());
    }

    void DeallocateMemory(MemoryAllocation* allocation) override {
    }

    uint64_t GetMemorySize() const override {
        return kHeapSize;
    }

    uint64_t GetMemoryAlignment() const override {
        return kHeapAlignment;
    }
};

class DummyBuddyMemoryAllocator {
  public:
    DummyBuddyMemoryAllocator(uint64_t maxBlockSize)
        : mAllocator(maxBlockSize, kHeapSize, kHeapAlignment, &mMemoryAllocator) {
    }

    DummyBuddyMemoryAllocator(uint64_t maxBlockSize, MemoryAllocator* memoryAllocator)
        : mAllocator(maxBlockSize, kHeapSize, kHeapAlignment, memoryAllocator) {
    }

    std::unique_ptr<MemoryAllocation> Allocate(uint64_t size, uint64_t alignment = kHeapAlignment) {
        std::unique_ptr<MemoryAllocation> allocation = mAllocator.AllocateMemory(size, alignment);
        if (allocation == nullptr) {
            return {};
        }
        return allocation;
    }

    void Deallocate(MemoryAllocation* allocation) {
        mAllocator.DeallocateMemory(allocation);
    }

    uint64_t GetSuballocatedMemorySizeForTesting() const {
        return mAllocator.GetSuballocatedMemorySizeForTesting();
    }

  private:
    DummyMemoryAllocator mMemoryAllocator;
    VirtualBuddyMemoryAllocator mAllocator;
};

// Verify a single resource allocation in a single heap.
TEST(VirtualBuddyMemoryAllocatorTests, SingleHeap) {
    // After one 128 byte resource allocation:
    //
    // max block size -> ---------------------------
    //                   |          A1/H0          |       Hi - Heap at index i
    // max heap size  -> ---------------------------       An - Resource allocation n
    //
    constexpr uint64_t maxBlockSize = kHeapSize;
    DummyBuddyMemoryAllocator allocator(maxBlockSize);

    // Cannot allocate greater than heap size.
    std::unique_ptr<MemoryAllocation> invalidAllocation = allocator.Allocate(kHeapSize * 2);
    ASSERT_EQ(invalidAllocation, nullptr);

    // Allocate one 128 byte allocation (same size as heap).
    std::unique_ptr<MemoryAllocation> allocation1 = allocator.Allocate(128);
    ASSERT_EQ(allocation1->GetInfo().mBlock->mOffset, 0u);
    ASSERT_EQ(allocation1->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);

    // Cannot allocate when allocator is full.
    invalidAllocation = allocator.Allocate(128);
    ASSERT_EQ(invalidAllocation, nullptr);

    allocator.Deallocate(allocation1.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 0u);
}

// Verify that multiple allocation are created in separate heaps.
TEST(VirtualBuddyMemoryAllocatorTests, MultipleHeaps) {
    // After two 128 byte resource allocations:
    //
    // max block size -> ---------------------------
    //                   |                         |       Hi - Heap at index i
    // max heap size  -> ---------------------------       An - Resource allocation n
    //                   |   A1/H0    |    A2/H1   |
    //                   ---------------------------
    //
    constexpr uint64_t maxBlockSize = 256;
    DummyBuddyMemoryAllocator allocator(maxBlockSize);

    // Cannot allocate greater than heap size.
    std::unique_ptr<MemoryAllocation> invalidAllocation = allocator.Allocate(kHeapSize * 2);
    ASSERT_EQ(invalidAllocation, nullptr);

    // Cannot allocate greater than max block size.
    invalidAllocation = allocator.Allocate(maxBlockSize * 2);
    ASSERT_EQ(invalidAllocation, nullptr);

    // Allocate two 128 byte allocations.
    std::unique_ptr<MemoryAllocation> allocation1 = allocator.Allocate(kHeapSize);
    ASSERT_EQ(allocation1->GetInfo().mBlock->mOffset, 0u);
    ASSERT_EQ(allocation1->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    // First allocation creates first heap.
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);

    std::unique_ptr<MemoryAllocation> allocation2 = allocator.Allocate(kHeapSize);
    ASSERT_EQ(allocation2->GetInfo().mBlock->mOffset, kHeapSize);
    ASSERT_EQ(allocation2->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    // Second allocation creates second heap.
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 2u);
    ASSERT_NE(allocation1->GetMemory(), allocation2->GetMemory());

    // Deallocate both allocations
    allocator.Deallocate(allocation1.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);  // Released H0

    allocator.Deallocate(allocation2.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 0u);  // Released H1
}

// Verify multiple sub-allocations can re-use heaps.
TEST(VirtualBuddyMemoryAllocatorTests, MultipleSplitHeaps) {
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
    DummyBuddyMemoryAllocator allocator(maxBlockSize);

    // Allocate two 64 byte sub-allocations.
    std::unique_ptr<MemoryAllocation> allocation1 = allocator.Allocate(kHeapSize / 2);
    ASSERT_EQ(allocation1->GetInfo().mBlock->mOffset, 0u);
    ASSERT_EQ(allocation1->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    // First sub-allocation creates first heap.
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);

    std::unique_ptr<MemoryAllocation> allocation2 = allocator.Allocate(kHeapSize / 2);
    ASSERT_EQ(allocation2->GetInfo().mBlock->mOffset, kHeapSize / 2);
    ASSERT_EQ(allocation2->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    // Second allocation re-uses first heap.
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);
    ASSERT_EQ(allocation1->GetMemory(), allocation2->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation3 = allocator.Allocate(kHeapSize / 2);
    ASSERT_EQ(allocation3->GetInfo().mBlock->mOffset, kHeapSize);
    ASSERT_EQ(allocation3->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    // Third allocation creates second heap.
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 2u);
    ASSERT_NE(allocation1->GetMemory(), allocation3->GetMemory());

    // Deallocate all allocations in reverse order.
    allocator.Deallocate(allocation1.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(),
              2u);  // A2 pins H0.

    allocator.Deallocate(allocation2.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);  // Released H0

    allocator.Deallocate(allocation3.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 0u);  // Released H1
}

// Verify resource sub-allocation of various sizes over multiple heaps.
TEST(VirtualBuddyMemoryAllocatorTests, MultiplSplitHeapsVariableSizes) {
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
    DummyBuddyMemoryAllocator allocator(maxBlockSize);

    // Allocate two 64-byte allocations.
    std::unique_ptr<MemoryAllocation> allocation1 = allocator.Allocate(64);
    ASSERT_EQ(allocation1->GetInfo().mBlock->mOffset, 0u);
    ASSERT_EQ(allocation1->GetOffset(), 0u);
    ASSERT_EQ(allocation1->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    std::unique_ptr<MemoryAllocation> allocation2 = allocator.Allocate(64);
    ASSERT_EQ(allocation2->GetInfo().mBlock->mOffset, 64u);
    ASSERT_EQ(allocation2->GetOffset(), 64u);
    ASSERT_EQ(allocation2->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    // A1 and A2 share H0
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);
    ASSERT_EQ(allocation1->GetMemory(), allocation2->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation3 = allocator.Allocate(128);
    ASSERT_EQ(allocation3->GetInfo().mBlock->mOffset, 128u);
    ASSERT_EQ(allocation3->GetOffset(), 0u);
    ASSERT_EQ(allocation3->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    // A3 creates and fully occupies a new heap.
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 2u);
    ASSERT_NE(allocation2->GetMemory(), allocation3->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation4 = allocator.Allocate(64);
    ASSERT_EQ(allocation4->GetInfo().mBlock->mOffset, 256u);
    ASSERT_EQ(allocation4->GetOffset(), 0u);
    ASSERT_EQ(allocation4->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 3u);
    ASSERT_NE(allocation3->GetMemory(), allocation4->GetMemory());

    // R5 size forms 64 byte hole after R4.
    std::unique_ptr<MemoryAllocation> allocation5 = allocator.Allocate(128);
    ASSERT_EQ(allocation5->GetInfo().mBlock->mOffset, 384u);
    ASSERT_EQ(allocation5->GetOffset(), 0u);
    ASSERT_EQ(allocation5->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 4u);
    ASSERT_NE(allocation4->GetMemory(), allocation5->GetMemory());

    // Deallocate allocations in staggered order.
    allocator.Deallocate(allocation1.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 4u);  // A2 pins H0

    allocator.Deallocate(allocation5.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 3u);  // Released H3

    allocator.Deallocate(allocation2.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 2u);  // Released H0

    allocator.Deallocate(allocation4.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);  // Released H2

    allocator.Deallocate(allocation3.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 0u);  // Released H1
}

// Verify resource sub-allocation of same sizes with various alignments.
TEST(VirtualBuddyMemoryAllocatorTests, SameSizeVariousAlignment) {
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
    DummyBuddyMemoryAllocator allocator(maxBlockSize);

    std::unique_ptr<MemoryAllocation> allocation1 = allocator.Allocate(64, 128);
    ASSERT_EQ(allocation1->GetInfo().mBlock->mOffset, 0u);
    ASSERT_EQ(allocation1->GetOffset(), 0u);
    ASSERT_EQ(allocation1->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);

    std::unique_ptr<MemoryAllocation> allocation2 = allocator.Allocate(64, 128);
    ASSERT_EQ(allocation2->GetInfo().mBlock->mOffset, 128u);
    ASSERT_EQ(allocation2->GetOffset(), 0u);
    ASSERT_EQ(allocation2->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 2u);
    ASSERT_NE(allocation1->GetMemory(), allocation2->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation3 = allocator.Allocate(64, 128);
    ASSERT_EQ(allocation3->GetInfo().mBlock->mOffset, 256u);
    ASSERT_EQ(allocation3->GetOffset(), 0u);
    ASSERT_EQ(allocation3->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 3u);
    ASSERT_NE(allocation2->GetMemory(), allocation3->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation4 = allocator.Allocate(64, 64);
    ASSERT_EQ(allocation4->GetInfo().mBlock->mOffset, 320u);
    ASSERT_EQ(allocation4->GetOffset(), 64u);
    ASSERT_EQ(allocation4->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 3u);
    ASSERT_EQ(allocation3->GetMemory(), allocation4->GetMemory());

    allocator.Deallocate(allocation1.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 2u);

    allocator.Deallocate(allocation2.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);

    allocator.Deallocate(allocation3.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);

    allocator.Deallocate(allocation4.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 0u);
}

// Verify resource sub-allocation of various sizes with same alignments.
TEST(VirtualBuddyMemoryAllocatorTests, VariousSizeSameAlignment) {
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
    DummyBuddyMemoryAllocator allocator(maxBlockSize);

    constexpr uint64_t alignment = 64;

    std::unique_ptr<MemoryAllocation> allocation1 = allocator.Allocate(64, alignment);
    ASSERT_EQ(allocation1->GetInfo().mBlock->mOffset, 0u);
    ASSERT_EQ(allocation1->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);

    std::unique_ptr<MemoryAllocation> allocation2 = allocator.Allocate(64, alignment);
    ASSERT_EQ(allocation2->GetInfo().mBlock->mOffset, 64u);
    ASSERT_EQ(allocation2->GetOffset(), 64u);
    ASSERT_EQ(allocation2->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);  // Reuses H0
    ASSERT_EQ(allocation1->GetMemory(), allocation2->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation3 = allocator.Allocate(128, alignment);
    ASSERT_EQ(allocation3->GetInfo().mBlock->mOffset, 128u);
    ASSERT_EQ(allocation3->GetOffset(), 0u);
    ASSERT_EQ(allocation3->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 2u);
    ASSERT_NE(allocation2->GetMemory(), allocation3->GetMemory());

    std::unique_ptr<MemoryAllocation> allocation4 = allocator.Allocate(128, alignment);
    ASSERT_EQ(allocation4->GetInfo().mBlock->mOffset, 256u);
    ASSERT_EQ(allocation4->GetOffset(), 0u);
    ASSERT_EQ(allocation4->GetInfo().mMethod, AllocationMethod::kSubAllocated);

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 3u);
    ASSERT_NE(allocation3->GetMemory(), allocation4->GetMemory());

    allocator.Deallocate(allocation1.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 3u);

    allocator.Deallocate(allocation2.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 2u);

    allocator.Deallocate(allocation3.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 1u);

    allocator.Deallocate(allocation4.get());
    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 0u);
}

// Verify allocating a very large resource does not overflow.
TEST(VirtualBuddyMemoryAllocatorTests, AllocationOverflow) {
    constexpr uint64_t maxBlockSize = 512;
    DummyBuddyMemoryAllocator allocator(maxBlockSize);

    constexpr uint64_t largeBlock = (1ull << 63) + 1;
    std::unique_ptr<MemoryAllocation> invalidAllocation = allocator.Allocate(largeBlock);
    ASSERT_EQ(invalidAllocation, nullptr);
}

// Verify resource heaps will be reused from a pool.
TEST(VirtualBuddyMemoryAllocatorTests, ReuseFreedHeaps) {
    constexpr uint64_t kMaxBlockSize = 4096;

    DummyMemoryAllocator memoryAllocator;
    LIFOPooledMemoryAllocator poolAllocator(&memoryAllocator);
    DummyBuddyMemoryAllocator allocator(kMaxBlockSize, &poolAllocator);

    std::set<MemoryBase*> heaps = {};
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};

    constexpr uint32_t kNumOfAllocations = 100;

    // Allocate |kNumOfAllocations|.
    for (uint32_t i = 0; i < kNumOfAllocations; i++) {
        std::unique_ptr<MemoryAllocation> allocation = allocator.Allocate(4);
        ASSERT_EQ(allocation->GetInfo().mMethod, AllocationMethod::kSubAllocated);
        heaps.insert(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    ASSERT_EQ(poolAllocator.GetPoolSizeForTesting(), 0u);

    // Return the allocations to the pool.
    for (auto& allocation : allocations) {
        allocator.Deallocate(allocation.get());
    }

    ASSERT_EQ(poolAllocator.GetPoolSizeForTesting(), heaps.size());

    allocations.clear();

    // Allocate again reusing the same heaps.
    for (uint32_t i = 0; i < kNumOfAllocations; i++) {
        std::unique_ptr<MemoryAllocation> allocation = allocator.Allocate(4);
        ASSERT_EQ(allocation->GetInfo().mMethod, AllocationMethod::kSubAllocated);
        ASSERT_FALSE(heaps.insert(allocation->GetMemory()).second);
        allocations.push_back(std::move(allocation));
    }

    ASSERT_EQ(poolAllocator.GetPoolSizeForTesting(), 0u);

    for (auto& allocation : allocations) {
        allocator.Deallocate(allocation.get());
    }

    ASSERT_EQ(allocator.GetSuballocatedMemorySizeForTesting(), 0u);

    poolAllocator.ReleaseMemory();
}

// Verify resource heaps that were reused from a pool can be destroyed.
TEST(VirtualBuddyMemoryAllocatorTests, DestroyHeaps) {
    constexpr uint64_t kMaxBlockSize = 4096;

    DummyMemoryAllocator memoryAllocator;
    LIFOPooledMemoryAllocator poolAllocator(&memoryAllocator);
    DummyBuddyMemoryAllocator allocator(kMaxBlockSize, &poolAllocator);

    std::set<MemoryBase*> heaps = {};
    std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};

    // Count by heap (vs number of allocations) to ensure there are exactly |kNumOfHeaps| worth of
    // buffers. Otherwise, the heap may be reused if not full.
    constexpr uint32_t kNumOfHeaps = 10;

    // Allocate |kNumOfHeaps| worth.
    while (heaps.size() < kNumOfHeaps) {
        std::unique_ptr<MemoryAllocation> allocation = allocator.Allocate(4);
        ASSERT_EQ(allocation->GetInfo().mMethod, AllocationMethod::kSubAllocated);
        heaps.insert(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    ASSERT_EQ(poolAllocator.GetPoolSizeForTesting(), 0u);

    // Return the allocations to the pool.
    for (auto& allocation : allocations) {
        allocator.Deallocate(allocation.get());
    }

    ASSERT_EQ(poolAllocator.GetPoolSizeForTesting(), kNumOfHeaps);

    poolAllocator.ReleaseMemory();
}
