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

#include "gpgmm/SlabBlockAllocator.h"
#include "gpgmm/common/Math.h"

#include <unordered_set>

using namespace gpgmm;

// Verify a single allocation in a slab.
TEST(SlabBlockAllocatorTests, SingleBlock) {
    constexpr uint64_t blockSize = 32;
    constexpr uint64_t slabSize = 128;
    SlabBlockAllocator allocator(slabSize / blockSize, blockSize);

    // Check that we cannot allocate a oversized block.
    EXPECT_EQ(allocator.AllocateBlock(slabSize * 2), nullptr);

    // Check that we cannot allocate a zero sized block.
    EXPECT_EQ(allocator.AllocateBlock(0u), nullptr);

    // Allocate the block.
    Block* block = allocator.AllocateBlock(blockSize);
    ASSERT_NE(block, nullptr);
    EXPECT_EQ(block->Offset, 0u);
    EXPECT_EQ(block->Size, blockSize);

    // Check that we are full.
    EXPECT_EQ(allocator.AllocateBlock(slabSize), nullptr);

    allocator.DeallocateBlock(block);
}

TEST(SlabBlockAllocatorTests, SingleBlockAligned) {
    constexpr uint64_t blockSize = 32;
    constexpr uint64_t slabSize = 128;
    SlabBlockAllocator allocator(slabSize / blockSize, blockSize);

    // Check that we cannot allocate a misaligned block.
    EXPECT_EQ(allocator.AllocateBlock(blockSize, 64u), nullptr);

    constexpr uint64_t alignment = 16u;
    Block* alignedBlock = allocator.AllocateBlock(blockSize, alignment);
    ASSERT_NE(alignedBlock, nullptr);
    EXPECT_TRUE(IsAligned(alignedBlock->Offset, alignment));
    allocator.DeallocateBlock(alignedBlock);
}

// Verify multiple contiguous allocations in a slab.
TEST(SlabBlockAllocatorTests, MultipleBlocks) {
    // Fill entire slab in the allocator.
    constexpr uint64_t blockSize = 32;
    constexpr uint64_t slabSize = 128;
    SlabBlockAllocator allocator(slabSize / blockSize, blockSize);

    std::unordered_set<Block*> blocks = {};
    for (uint64_t blockIdx = 0; blockIdx < slabSize / blockSize; blockIdx++) {
        Block* block = allocator.AllocateBlock(blockSize);
        ASSERT_NE(block, nullptr);
        EXPECT_EQ(block->Offset, blockSize * blockIdx);
        EXPECT_TRUE(blocks.insert(block).second);
    }

    // Check that we are full.
    EXPECT_EQ(allocator.AllocateBlock(blockSize), nullptr);

    for (Block* block : blocks) {
        allocator.DeallocateBlock(block);
    }

    // Check that we are empty.
    EXPECT_NE(allocator.AllocateBlock(blockSize), nullptr);
}

// Verify multiple non-contiguous allocations in a slab.
TEST(SlabBlockAllocatorTests, MultipleBlocksVarious) {
    // Fill entire slab in the allocator.
    constexpr uint64_t blockSize = 32;
    constexpr uint64_t slabSize = 128;
    SlabBlockAllocator allocator(slabSize / blockSize, blockSize);

    std::unordered_set<Block*> blocks = {};

    // Create three contiguous blocks.
    Block* blockA = nullptr;
    {
        blockA = allocator.AllocateBlock(blockSize);
        ASSERT_NE(blockA, nullptr);
        EXPECT_TRUE(blocks.insert(blockA).second);
        EXPECT_EQ(blockA->Offset, 0u);
    }

    Block* blockB = nullptr;
    {
        blockB = allocator.AllocateBlock(blockSize);
        ASSERT_NE(blockB, nullptr);
        EXPECT_TRUE(blocks.insert(blockB).second);
        EXPECT_EQ(blockB->Offset, blockSize);
    }

    Block* blockC = nullptr;
    {
        blockC = allocator.AllocateBlock(blockSize);
        ASSERT_NE(blockC, nullptr);
        EXPECT_TRUE(blocks.insert(blockC).second);
        EXPECT_EQ(blockC->Offset, blockSize * 2);
    }

    // De-allocate them in a random order (and not contigious).
    allocator.DeallocateBlock(blockB);
    allocator.DeallocateBlock(blockC);
    allocator.DeallocateBlock(blockA);

    // Re-allocate should reuse.
    blockA = allocator.AllocateBlock(blockSize);
    ASSERT_NE(blockA, nullptr);
    EXPECT_FALSE(blocks.insert(blockA).second);

    blockB = allocator.AllocateBlock(blockSize);
    ASSERT_NE(blockB, nullptr);
    EXPECT_FALSE(blocks.insert(blockB).second);

    blockC = allocator.AllocateBlock(blockSize);
    ASSERT_NE(blockC, nullptr);
    EXPECT_FALSE(blocks.insert(blockC).second);

    // De-allocate them in a different random order (and not contigious).
    allocator.DeallocateBlock(blockA);
    allocator.DeallocateBlock(blockC);
    allocator.DeallocateBlock(blockB);
}
