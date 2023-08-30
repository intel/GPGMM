// Copyright 2019 The Dawn Authors
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

#include "gpgmm/common/BuddyBlockAllocator.h"

using namespace gpgmm;

class DummyBuddyBlockAllocator {
  public:
    DummyBuddyBlockAllocator(uint64_t maxBlockSize) : mAllocator(maxBlockSize) {
    }

    MemoryBlock* TryAllocateBlock(uint64_t requestSize, uint64_t alignment = 1) {
        return mAllocator.TryAllocateBlock(requestSize, alignment).AcquireResult();
    }

    void DeallocateBlock(MemoryBlock* block) {
        mAllocator.DeallocateBlock(block);
    }

    uint64_t ComputeTotalNumOfFreeBlocksForTesting() const {
        return mAllocator.ComputeTotalNumOfFreeBlocksForTesting();
    }

    BuddyBlockAllocator mAllocator;
};

// Verify the buddy allocator with a basic test.
TEST(BuddyBlockAllocatorTests, SingleBlock) {
    // After one 32 byte allocation:
    //
    //  Level          --------------------------------
    //      0       32 |               A              |
    //                 --------------------------------
    //
    constexpr uint64_t maxBlockSize = 32;
    DummyBuddyBlockAllocator allocator(maxBlockSize);

    // Check that we cannot allocate a oversized block.
    ASSERT_EQ(allocator.TryAllocateBlock(maxBlockSize * 2), nullptr);

    // Allocate the block.
    MemoryBlock* block = allocator.TryAllocateBlock(maxBlockSize);
    ASSERT_EQ(block->Offset, 0u);

    // Check that we are full.
    ASSERT_EQ(allocator.TryAllocateBlock(maxBlockSize), nullptr);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 0u);

    // Deallocate the block.
    allocator.DeallocateBlock(block);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);
}

// Verify multiple allocations succeeds using a buddy allocator.
TEST(BuddyBlockAllocatorTests, MultipleBlocks) {
    // Fill every level in the allocator (order-n = 2^n)
    const uint64_t maxBlockSize = (1ull << 16);
    for (uint64_t order = 1; (1ull << order) <= maxBlockSize; order++) {
        DummyBuddyBlockAllocator allocator(maxBlockSize);

        uint64_t blockSize = (1ull << order);
        for (uint32_t blocki = 0; blocki < (maxBlockSize / blockSize); blocki++) {
            ASSERT_EQ(allocator.TryAllocateBlock(blockSize)->Offset, blockSize * blocki);
        }
    }
}

// Verify that a single allocation succeeds using a buddy allocator.
TEST(BuddyBlockAllocatorTests, SingleSplitBlock) {
    //  After one 8 byte allocation:
    //
    //  Level          --------------------------------
    //      0       32 |               S              |
    //                 --------------------------------
    //      1       16 |       S       |       F      |        S - split
    //                 --------------------------------        F - free
    //      2       8  |   A   |   F   |       |      |        A - allocated
    //                 --------------------------------
    //
    constexpr uint64_t maxBlockSize = 32;
    DummyBuddyBlockAllocator allocator(maxBlockSize);

    // Allocate block (splits two blocks).
    MemoryBlock* block = allocator.TryAllocateBlock(8);
    ASSERT_EQ(block->Offset, 0u);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 2u);

    // Deallocate block (merges two blocks).
    allocator.DeallocateBlock(block);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);

    // Check that we cannot allocate a block that is oversized.
    ASSERT_EQ(allocator.TryAllocateBlock(maxBlockSize * 2), nullptr);

    // Re-allocate the largest block allowed after merging.
    block = allocator.TryAllocateBlock(maxBlockSize);
    ASSERT_EQ(block->Offset, 0u);

    allocator.DeallocateBlock(block);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);
}

// Verify that a multiple allocated blocks can be removed in the free-list.
TEST(BuddyBlockAllocatorTests, MultipleSplitBlocks) {
    //  After four 16 byte allocations:
    //
    //  Level          --------------------------------
    //      0       32 |               S              |
    //                 --------------------------------
    //      1       16 |       S       |       S      |        S - split
    //                 --------------------------------        F - free
    //      2       8  |   Aa  |   Ab  |  Ac  |   Ad  |        A - allocated
    //                 --------------------------------
    //
    constexpr uint64_t maxBlockSize = 32;
    DummyBuddyBlockAllocator allocator(maxBlockSize);

    // Populates the free-list with four blocks at Level2.

    // Allocate "a" block (two splits).
    constexpr uint64_t blockSizeInBytes = 8;
    MemoryBlock* blockA = allocator.TryAllocateBlock(blockSizeInBytes);
    ASSERT_EQ(blockA->Offset, 0u);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 2u);

    // Allocate "b" block.
    MemoryBlock* blockB = allocator.TryAllocateBlock(blockSizeInBytes);
    ASSERT_EQ(blockB->Offset, blockSizeInBytes);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);

    // Allocate "c" block (three splits).
    MemoryBlock* blockC = allocator.TryAllocateBlock(blockSizeInBytes);
    ASSERT_EQ(blockC->Offset, blockB->Offset + blockSizeInBytes);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);

    // Allocate "d" block.
    MemoryBlock* blockD = allocator.TryAllocateBlock(blockSizeInBytes);
    ASSERT_EQ(blockD->Offset, blockC->Offset + blockSizeInBytes);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 0u);

    // Deallocate "d" block.
    // FreeList[Level2] = [BlockD] -> x
    allocator.DeallocateBlock(blockD);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);

    // Deallocate "b" block.
    // FreeList[Level2] = [BlockB] -> [BlockD] -> x
    allocator.DeallocateBlock(blockB);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 2u);

    // Deallocate "c" block (one merges).
    // FreeList[Level1] = [BlockCD] -> x
    // FreeList[Level2] = [BlockB] -> x
    allocator.DeallocateBlock(blockC);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 2u);

    // Deallocate "a" block (two merges).
    // FreeList[Level0] = [BlockABCD] -> x
    allocator.DeallocateBlock(blockA);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);
}

// Verify the buddy allocator can handle allocations of various sizes.
TEST(BuddyBlockAllocatorTests, MultipleSplitBlockIncreasingSize) {
    //  After four Level4-to-Level1 byte then one L4 block allocations:
    //
    //  Level          -----------------------------------------------------------------
    //      0      512 |                               S                               |
    //                 -----------------------------------------------------------------
    //      1      256 |               S               |               A               |
    //                 -----------------------------------------------------------------
    //      2      128 |       S       |       A       |               |               |
    //                 -----------------------------------------------------------------
    //      3       64 |   S   |   A   |       |       |       |       |       |       |
    //                 -----------------------------------------------------------------
    //      4       32 | A | F |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
    //                 -----------------------------------------------------------------
    //
    constexpr uint64_t maxBlockSize = 512;
    DummyBuddyBlockAllocator allocator(maxBlockSize);

    ASSERT_EQ(allocator.TryAllocateBlock(32)->Offset, 0ull);
    ASSERT_EQ(allocator.TryAllocateBlock(64)->Offset, 64ull);
    ASSERT_EQ(allocator.TryAllocateBlock(128)->Offset, 128ull);
    ASSERT_EQ(allocator.TryAllocateBlock(256)->Offset, 256ull);

    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);

    // Fill in the last free block.
    ASSERT_EQ(allocator.TryAllocateBlock(32)->Offset, 32ull);

    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 0u);

    // Check if we're full.
    ASSERT_EQ(allocator.TryAllocateBlock(32), nullptr);
}

// Verify very small allocations using a larger allocator works correctly.
TEST(BuddyBlockAllocatorTests, MultipleSplitBlocksVariableSizes) {
    //  After allocating four pairs of one 64 byte block and one 32 byte block.
    //
    //  Level          -----------------------------------------------------------------
    //      0      512 |                               S                               |
    //                 -----------------------------------------------------------------
    //      1      256 |               S               |               S               |
    //                 -----------------------------------------------------------------
    //      2      128 |       S       |       S       |       S       |       F       |
    //                 -----------------------------------------------------------------
    //      3       64 |   A   |   S   |   A   |   A   |   S   |   A   |       |       |
    //                 -----------------------------------------------------------------
    //      4       32 |   |   | A | A |   |   |   |   | A | A |   |   |   |   |   |   |
    //                 -----------------------------------------------------------------
    //
    constexpr uint64_t maxBlockSize = 512;
    DummyBuddyBlockAllocator allocator(maxBlockSize);

    ASSERT_EQ(allocator.TryAllocateBlock(64)->Offset, 0ull);
    ASSERT_EQ(allocator.TryAllocateBlock(32)->Offset, 64ull);

    ASSERT_EQ(allocator.TryAllocateBlock(64)->Offset, 128ull);
    ASSERT_EQ(allocator.TryAllocateBlock(32)->Offset, 96ull);

    ASSERT_EQ(allocator.TryAllocateBlock(64)->Offset, 192ull);
    ASSERT_EQ(allocator.TryAllocateBlock(32)->Offset, 256ull);

    ASSERT_EQ(allocator.TryAllocateBlock(64)->Offset, 320ull);
    ASSERT_EQ(allocator.TryAllocateBlock(32)->Offset, 288ull);

    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);
}

// Verify the buddy allocator can deal with bad fragmentation.
TEST(BuddyBlockAllocatorTests, MultipleSplitBlocksInterleaved) {
    //  Allocate every leaf then de-allocate every other of those allocations.
    //
    //  Level          -----------------------------------------------------------------
    //      0      512 |                               S                               |
    //                 -----------------------------------------------------------------
    //      1      256 |               S               |               S               |
    //                 -----------------------------------------------------------------
    //      2      128 |       S       |       S       |        S       |        S     |
    //                 -----------------------------------------------------------------
    //      3       64 |   S   |   S   |   S   |   S   |   S   |   S   |   S   |   S   |
    //                 -----------------------------------------------------------------
    //      4       32 | A | F | A | F | A | F | A | F | A | F | A | F | A | F | A | F |
    //                 -----------------------------------------------------------------
    //
    constexpr uint64_t maxBlockSize = 512;
    DummyBuddyBlockAllocator allocator(maxBlockSize);

    // Allocate leaf blocks
    constexpr uint64_t minBlockSizeInBytes = 32;
    std::vector<MemoryBlock*> blocks;
    for (uint64_t i = 0; i < maxBlockSize / minBlockSizeInBytes; i++) {
        blocks.push_back(allocator.TryAllocateBlock(minBlockSizeInBytes));
    }

    // Free every other leaf block.
    for (size_t count = 1; count < blocks.size(); count += 2) {
        allocator.DeallocateBlock(blocks[count]);
    }

    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 8u);
}

// Verify the buddy allocator can deal with multiple allocations with mixed alignments.
TEST(BuddyBlockAllocatorTests, SameSizeVariousAlignment) {
    //  After two 8 byte allocations with 16 byte alignment then one 8 byte allocation with 8 byte
    //  alignment.
    //
    //  Level          --------------------------------
    //      0       32 |               S              |
    //                 --------------------------------
    //      1       16 |       S       |       S      |       S - split
    //                 --------------------------------       F - free
    //      2       8  |   Aa  |   F   |  Ab   |  Ac  |       A - allocated
    //                 --------------------------------
    //
    DummyBuddyBlockAllocator allocator(32);

    // Allocate Aa (two splits).
    ASSERT_EQ(allocator.TryAllocateBlock(8, 16)->Offset, 0u);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 2u);

    // Allocate Ab (skip Aa buddy due to alignment and perform another split).
    ASSERT_EQ(allocator.TryAllocateBlock(8, 16)->Offset, 16u);

    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 2u);

    // Check that we cannot fit another.
    ASSERT_EQ(allocator.TryAllocateBlock(8, 16), nullptr);

    // Allocate Ac (zero splits and Ab's buddy is now the first free block).
    ASSERT_EQ(allocator.TryAllocateBlock(8, 8)->Offset, 24u);

    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);
}

// Verify the buddy allocator can deal with multiple allocations with equal alignments.
TEST(BuddyBlockAllocatorTests, VariousSizeSameAlignment) {
    //  After two 8 byte allocations with 4 byte alignment then one 16 byte allocation with 4 byte
    //  alignment.
    //
    //  Level          --------------------------------
    //      0       32 |               S              |
    //                 --------------------------------
    //      1       16 |       S       |       Ac     |       S - split
    //                 --------------------------------       F - free
    //      2       8  |   Aa  |   Ab  |              |       A - allocated
    //                 --------------------------------
    //
    constexpr uint64_t maxBlockSize = 32;
    constexpr uint64_t alignment = 4;
    DummyBuddyBlockAllocator allocator(maxBlockSize);

    // Allocate block Aa (two splits)
    ASSERT_EQ(allocator.TryAllocateBlock(8, alignment)->Offset, 0u);
    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 2u);

    // Allocate block Ab (Aa's buddy)
    ASSERT_EQ(allocator.TryAllocateBlock(8, alignment)->Offset, 8u);

    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 1u);

    // Check that we can still allocate Ac.
    ASSERT_EQ(allocator.TryAllocateBlock(16, alignment)->Offset, 16ull);

    ASSERT_EQ(allocator.ComputeTotalNumOfFreeBlocksForTesting(), 0u);
}
