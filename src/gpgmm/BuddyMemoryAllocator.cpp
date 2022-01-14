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

#include "gpgmm/BuddyMemoryAllocator.h"

#include "gpgmm/Memory.h"
#include "gpgmm/TraceEvent.h"
#include "gpgmm/common/Math.h"

namespace gpgmm {

    BuddyMemoryAllocator::BuddyMemoryAllocator(uint64_t systemSize,
                                               uint64_t memorySize,
                                               uint64_t memoryAlignment,
                                               MemoryAllocator* memoryAllocator)
        : mMemoryAllocator(memoryAllocator),
          mMemorySize(memorySize),
          mMemoryAlignment(memoryAlignment),
          mBuddyBlockAllocator(systemSize) {
        ASSERT(mMemorySize <= systemSize);
        ASSERT(IsPowerOfTwo(mMemorySize));
        ASSERT(systemSize % mMemorySize == 0);
    }

    BuddyMemoryAllocator::~BuddyMemoryAllocator() {
        ASSERT(mPool.GetPoolSize() == 0);
    }

    uint64_t BuddyMemoryAllocator::GetMemoryIndex(uint64_t offset) const {
        ASSERT(offset != kInvalidOffset);
        return offset / mMemorySize;
    }

    std::unique_ptr<MemoryAllocation> BuddyMemoryAllocator::TryAllocateMemory(uint64_t size,
                                                                              uint64_t alignment,
                                                                              bool neverAllocate) {
        TRACE_EVENT_CALL_SCOPED("BuddyMemoryAllocator.TryAllocateMemory");

        // Check the unaligned size to avoid overflowing NextPowerOfTwo.
        if (size == 0 || size > mMemorySize) {
            return nullptr;
        }

        // Round allocation size to nearest power-of-two.
        size = NextPowerOfTwo(size);

        // Allocation cannot exceed the memory size.
        if (size > mMemorySize) {
            return nullptr;
        }

        // Attempt to sub-allocate a block of the requested size.
        std::unique_ptr<MemoryAllocation> subAllocation = TrySubAllocateMemory(
            &mBuddyBlockAllocator, size, alignment, [&](auto block) -> MemoryBase* {
                const uint64_t memoryIndex = GetMemoryIndex(block->Offset);
                std::unique_ptr<MemoryAllocation> memoryAllocation =
                    mPool.AcquireFromPool(memoryIndex);

                // No existing, allocate new memory for the block.
                if (memoryAllocation == nullptr) {
                    GPGMM_TRY_ASSIGN(mMemoryAllocator->TryAllocateMemory(
                                         mMemorySize, mMemoryAlignment, neverAllocate),
                                     memoryAllocation);
                }

                MemoryBase* memory = memoryAllocation->GetMemory();
                mPool.ReturnToPool(std::move(memoryAllocation), memoryIndex);

                return memory;
            });

        if (subAllocation == nullptr) {
            return nullptr;
        }

        Block* block = subAllocation->GetBlock();
        mStats.UsedBlockCount++;
        mStats.UsedBlockUsage += block->Size;

        // Memory allocation offset is always memory-relative.
        const uint64_t memoryOffset = block->Offset % mMemorySize;

        return std::make_unique<MemoryAllocation>(/*allocator*/ this, subAllocation->GetMemory(),
                                                  memoryOffset, AllocationMethod::kSubAllocated,
                                                  block);
    }

    void BuddyMemoryAllocator::DeallocateMemory(MemoryAllocation* subAllocation) {
        TRACE_EVENT_CALL_SCOPED("BuddyMemoryAllocator.DeallocateMemory");

        ASSERT(subAllocation != nullptr);

        mStats.UsedBlockCount--;
        mStats.UsedBlockUsage -= subAllocation->GetSize();

        const uint64_t memoryIndex = GetMemoryIndex(subAllocation->GetBlock()->Offset);

        mBuddyBlockAllocator.DeallocateBlock(subAllocation->GetBlock());

        std::unique_ptr<MemoryAllocation> memoryAllocation = mPool.AcquireFromPool(memoryIndex);

        MemoryBase* memory = memoryAllocation->GetMemory();
        ASSERT(memory != nullptr);

        if (memory->Unref()) {
            mMemoryAllocator->DeallocateMemory(memoryAllocation.release());
        } else {
            mPool.ReturnToPool(std::move(memoryAllocation), memoryIndex);
        }
    }

    uint64_t BuddyMemoryAllocator::GetMemorySize() const {
        return mMemorySize;
    }

    uint64_t BuddyMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAlignment;
    }

    uint64_t BuddyMemoryAllocator::GetPoolSizeForTesting() const {
        return mPool.GetPoolSize();
    }

}  // namespace gpgmm
