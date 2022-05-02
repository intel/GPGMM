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

#ifndef GPGMM_COMMON_BUDDYBLOCKALLOCATOR_H_
#define GPGMM_COMMON_BUDDYBLOCKALLOCATOR_H_

#include "gpgmm/common/BlockAllocator.h"
#include "gpgmm/utils/Limits.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace gpgmm {

    // Buddy allocator uses the buddy memory allocation technique to satisfy an allocation request.
    // Memory is split into halves until just large enough to fit to the request. This
    // requires the allocation size to be a power-of-two value. The allocator "allocates" a block by
    // returning the starting offset whose size is guaranteed to be greater than or equal to the
    // allocation size. To deallocate, the same offset is used to find the corresponding block.
    //
    // Internally, it manages a free list to track free blocks in a full binary tree.
    // Every index in the free list corresponds to a level in the tree. That level also determines
    // the size of the block to be used to satisfy the request. The first level (index=0) represents
    // the root whose size is also called the max block size.
    //
    class BuddyBlockAllocator : public BlockAllocator {
      public:
        explicit BuddyBlockAllocator(uint64_t maxBlockSize);
        ~BuddyBlockAllocator() override;

        // BlockAllocator interface
        MemoryBlock* TryAllocateBlock(uint64_t requestSize, uint64_t alignment) override;
        void DeallocateBlock(MemoryBlock* block) override;

        // For testing purposes only.
        uint64_t ComputeTotalNumOfFreeBlocksForTesting() const;

        const char* GetTypename() const override;

      private:
        uint32_t ComputeLevelFromBlockSize(uint64_t blockSize) const;
        uint64_t GetNextFreeAlignedBlock(size_t allocationBlockLevel, uint64_t alignment) const;

        enum class BlockState { Free, Split, Allocated };

        struct BuddyBlock : public MemoryBlock {
            BuddyBlock() {
                free = {};
            }

            // Pointer to this block's buddy, iff parent is split.
            // Used to quickly merge buddy blocks upon de-allocate.
            BuddyBlock* pBuddy = nullptr;
            BuddyBlock* pParent = nullptr;

            // Track whether this block has been split or not.
            BlockState mState = BlockState::Free;

            struct FreeLinks {
                BuddyBlock* pPrev = nullptr;
                BuddyBlock* pNext = nullptr;
            };

            struct SplitLink {
                BuddyBlock* pLeft = nullptr;
            };

            union {
                // Used upon allocation.
                // Avoids searching for the next free block.
                FreeLinks free;

                // Used upon de-allocation.
                // Had this block split upon allocation, it and it's buddy is to be deleted.
                SplitLink split;
            };
        };

        void InsertFreeBlock(BuddyBlock* block, size_t level);
        void RemoveFreeBlock(BuddyBlock* block, size_t level);
        void DeleteBlock(BuddyBlock* block);

        uint64_t ComputeNumOfFreeBlocks(BuddyBlock* block) const;

        // Keep track the head and tail (for faster insertion/removal).
        struct BlockList {
            BuddyBlock* head = nullptr;  // First free block in level.
            // TODO(crbug.com/dawn/827): Track the tail.
        };

        BuddyBlock* mRoot = nullptr;  // Used to deallocate non-free blocks.

        uint64_t mMaxBlockSize = 0;

        // List of linked-lists of free blocks where the index is a level that
        // corresponds to a power-of-two sized block.
        std::vector<BlockList> mFreeLists;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_BUDDYBLOCKALLOCATOR_H_
