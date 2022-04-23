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

#ifndef GPGMM_SLABBLOCKALLOCATOR_H_
#define GPGMM_SLABBLOCKALLOCATOR_H_

#include "gpgmm/BlockAllocator.h"

namespace gpgmm {

    // SlabBlockAllocator uses the slab allocation technique to satisfy an
    // a block-allocation request. A slab consists of contiguious memory carved up into
    // fixed-size blocks (also called "pages" or "chunks"). The slab allocator
    // allocates within a slab by marking a block as "used" by removing it from
    // the free-list. To deallocate, the same block is marked "free" by inserting it
    // back to the free-list. This simple push/pop operation means
    // slab block allocation is always fast.
    class SlabBlockAllocator final : public BlockAllocator {
      public:
        SlabBlockAllocator() = default;
        SlabBlockAllocator(uint64_t blockCount, uint64_t blockSize);
        ~SlabBlockAllocator() override;

        // BlockAllocator interface
        MemoryBlock* TryAllocateBlock(uint64_t size, uint64_t alignment = 1) override;
        void DeallocateBlock(MemoryBlock* block) override;

        const char* GetTypename() const override;

      private:
        struct SlabBlock : public MemoryBlock {
            SlabBlock* pNext = nullptr;
        };

        struct BlockList {
            SlabBlock* pHead = nullptr;  // First free block in slab.
        };

        BlockList mFreeList;

        uint64_t mBlockCount = kInvalidSize;
        uint64_t mBlockSize = kInvalidSize;

        uint64_t mNextFreeBlockIndex = kInvalidIndex;  // Next index or "slot" in the slab.
    };

}  // namespace gpgmm

#endif  // GPGMM_SLABBLOCKALLOCATOR_H_
