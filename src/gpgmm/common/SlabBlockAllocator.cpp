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

#include "gpgmm/common/SlabBlockAllocator.h"

#include "gpgmm/common/Error.h"
#include "gpgmm/common/EventMessage.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Math.h"
#include "gpgmm/utils/Utils.h"

namespace gpgmm {

    SlabBlockAllocator::SlabBlockAllocator(uint64_t blockCount, uint64_t blockSize)
        : mBlockCount(blockCount), mBlockSize(blockSize), mNextFreeBlockIndex(0) {
        ASSERT(mBlockCount > 0);
        ASSERT(mBlockSize > 0);

        SlabBlock* head = new SlabBlock{};
        head->Offset = 0;
        head->Size = blockSize;
        mFreeList.pHead = head;
    }

    SlabBlockAllocator::SlabBlockAllocator(const SlabBlockAllocator& other)
        : mFreeList(other.mFreeList),
          mBlockCount(other.mBlockCount),
          mBlockSize(other.mBlockSize),
          mNextFreeBlockIndex(other.mNextFreeBlockIndex) {
    }

    SlabBlockAllocator& SlabBlockAllocator::operator=(const SlabBlockAllocator& other) {
        if (this == &other) {
            return *this;
        }
        mFreeList = other.mFreeList;
        mBlockCount = other.mBlockCount;
        mBlockSize = other.mBlockSize;
        mNextFreeBlockIndex = other.mNextFreeBlockIndex;
        return *this;
    }

    void SlabBlockAllocator::ReleaseBlocks() {
        SlabBlock* head = mFreeList.pHead;
        while (head != nullptr) {
            ASSERT(head != nullptr);
            SlabBlock* next = head->pNext;
            SafeDelete(head);
            head = next;
        }

        // Invalidate the head to prevent calling ReleaseBlocks() again resulting into a
        // use-after-free.
        mFreeList.pHead = nullptr;
    }

    MemoryBlock* SlabBlockAllocator::TryAllocateBlock(uint64_t requestSize, uint64_t alignment) {
        // Requested cannot exceed block size.
        if (requestSize > mBlockSize) {
            return nullptr;
        }

        // Offset must be equal to a multiple of |mBlockSize|.
        if (!IsAligned(mBlockSize, alignment)) {
            return nullptr;
        }

        // Pop off HEAD in the free-list.
        SlabBlock* head = mFreeList.pHead;
        if (head == nullptr) {
            mFreeList.pHead = nullptr;
        } else {
            mFreeList.pHead = mFreeList.pHead->pNext;
        }

        // And push new block at HEAD if not full.
        if (mFreeList.pHead == nullptr && mNextFreeBlockIndex + 1 < mBlockCount) {
            mFreeList.pHead = new SlabBlock{};
            mFreeList.pHead->Offset = ++mNextFreeBlockIndex * mBlockSize;
            mFreeList.pHead->Size = mBlockSize;
        }

        return head;
    }

    void SlabBlockAllocator::DeallocateBlock(MemoryBlock* block) {
        ASSERT(block != nullptr);

        SlabBlock* currBlock = static_cast<SlabBlock*>(block);

        // Push block to HEAD
        SlabBlock* head = mFreeList.pHead;
        mFreeList.pHead = currBlock;
        currBlock->pNext = head;
    }

    uint64_t SlabBlockAllocator::GetBlockCount() const {
        return mBlockCount;
    }

}  // namespace gpgmm
