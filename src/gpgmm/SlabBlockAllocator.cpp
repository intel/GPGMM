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

#include "gpgmm/SlabBlockAllocator.h"

#include "gpgmm/Debug.h"
#include "gpgmm/Error.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Math.h"
#include "gpgmm/utils/Utils.h"

namespace gpgmm {

    SlabBlockAllocator::SlabBlockAllocator(uint64_t blockCount, uint64_t blockSize)
        : mBlockCount(blockCount), mBlockSize(blockSize), mNextFreeBlockIndex(0) {
        SlabBlock* head = new SlabBlock{};
        head->Offset = 0;
        head->Size = blockSize;
        mFreeList.pHead = head;
    }

    SlabBlockAllocator::~SlabBlockAllocator() {
        SlabBlock* head = mFreeList.pHead;
        while (head != nullptr) {
            ASSERT(head != nullptr);
            SlabBlock* next = head->pNext;
            SafeDelete(head);
            head = next;
        }
    }

    MemoryBlock* SlabBlockAllocator::TryAllocateBlock(uint64_t requestSize, uint64_t alignment) {
        GPGMM_CHECK_NONZERO(requestSize);

        if (requestSize > mBlockSize) {
            InfoEvent("SlabBlockAllocator.TryAllocateBlock", ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED)
                << "Allocation size exceeded the block size. (" + std::to_string(requestSize) +
                       " vs " + std::to_string(mBlockSize) + " bytes).";
            return nullptr;
        }

        // Offset must be equal to a multiple of |mBlockSize|.
        if (!IsAligned(mBlockSize, alignment)) {
            InfoEvent("SlabBlockAllocator.TryAllocateBlock",
                      ALLOCATOR_MESSAGE_ID_ALIGNMENT_MISMATCH)
                << "Allocation alignment is not a multiple of the block size. (" +
                       std::to_string(alignment) + " vs " + std::to_string(mBlockSize) + " bytes).";
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

    const char* SlabBlockAllocator::GetTypename() const {
        return "SlabBlockAllocator";
    }

}  // namespace gpgmm
