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

#include "gpgmm/Debug.h"
#include "gpgmm/Memory.h"
#include "gpgmm/common/Math.h"

namespace gpgmm {

    BuddyMemoryAllocator::BuddyMemoryAllocator(uint64_t systemSize,
                                               uint64_t memorySize,
                                               uint64_t memoryAlignment,
                                               std::unique_ptr<MemoryAllocator> memoryAllocator)
        : MemoryAllocator(std::move(memoryAllocator)),
          mMemorySize(memorySize),
          mMemoryAlignment(memoryAlignment),
          mBuddyBlockAllocator(systemSize),
          mPool(mMemorySize) {
        ASSERT(mMemorySize <= systemSize);
        ASSERT(IsPowerOfTwo(mMemorySize));
        ASSERT(IsAligned(systemSize, mMemorySize));
    }

    uint64_t BuddyMemoryAllocator::GetMemoryIndex(uint64_t offset) const {
        ASSERT(offset != kInvalidOffset);
        return offset / mMemorySize;
    }

    std::unique_ptr<MemoryAllocation> BuddyMemoryAllocator::TryAllocateMemory(
        uint64_t allocationSize,
        uint64_t alignment,
        bool neverAllocate,
        bool cacheSize) {
        TRACE_EVENT_CALL_SCOPED("BuddyMemoryAllocator.TryAllocateMemory");

        // Check the unaligned size to avoid overflowing NextPowerOfTwo.
        if (allocationSize == 0 || allocationSize > mMemorySize) {
            RecordLogMessage(LogSeverity::Debug, "BuddyMemoryAllocator.TryAllocateMemory",
                             "Allocation size exceeded the memory size (" +
                                 std::to_string(allocationSize) + " vs " +
                                 std::to_string(mMemorySize) + " bytes).",
                             ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED);
            return nullptr;
        }

        // Round allocation size to nearest power-of-two.
        allocationSize = NextPowerOfTwo(allocationSize);

        // Allocation cannot exceed the memory size.
        if (allocationSize > mMemorySize) {
            RecordLogMessage(LogSeverity::Debug, "BuddyMemoryAllocator.TryAllocateMemory",
                             "Aligned allocation size exceeded the memory size (" +
                                 std::to_string(allocationSize) + " vs " +
                                 std::to_string(mMemorySize) + " bytes).",
                             ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED);

            return nullptr;
        }

        // Attempt to sub-allocate a block of the requested size.
        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(
            TrySubAllocateMemory(&mBuddyBlockAllocator, allocationSize, alignment,
                                 [&](const auto& block) -> MemoryBase* {
                                     const uint64_t memoryIndex = GetMemoryIndex(block->Offset);
                                     std::unique_ptr<MemoryAllocation> memoryAllocation =
                                         mPool.AcquireFromPool(memoryIndex);

                                     // No existing, allocate new memory for the block.
                                     if (memoryAllocation == nullptr) {
                                         GPGMM_TRY_ASSIGN(GetFirstChild()->TryAllocateMemory(
                                                              mMemorySize, mMemoryAlignment,
                                                              neverAllocate, cacheSize),
                                                          memoryAllocation);
                                     }

                                     MemoryBase* memory = memoryAllocation->GetMemory();
                                     mPool.ReturnToPool(std::move(memoryAllocation), memoryIndex);

                                     return memory;
                                 }),
            subAllocation);

        Block* block = subAllocation->GetBlock();
        mInfo.UsedBlockCount++;
        mInfo.UsedBlockUsage += block->Size;

        // Memory allocation offset is always memory-relative.
        const uint64_t memoryOffset = block->Offset % mMemorySize;

        return std::make_unique<MemoryAllocation>(/*allocator*/ this, subAllocation->GetMemory(),
                                                  memoryOffset, AllocationMethod::kSubAllocated,
                                                  block);
    }

    void BuddyMemoryAllocator::DeallocateMemory(MemoryAllocation* subAllocation) {
        TRACE_EVENT_CALL_SCOPED("BuddyMemoryAllocator.DeallocateMemory");

        ASSERT(subAllocation != nullptr);

        mInfo.UsedBlockCount--;
        mInfo.UsedBlockUsage -= subAllocation->GetSize();

        const uint64_t memoryIndex = GetMemoryIndex(subAllocation->GetBlock()->Offset);

        mBuddyBlockAllocator.DeallocateBlock(subAllocation->GetBlock());

        std::unique_ptr<MemoryAllocation> memoryAllocation = mPool.AcquireFromPool(memoryIndex);

        MemoryBase* memory = memoryAllocation->GetMemory();
        ASSERT(memory != nullptr);

        if (memory->Unref()) {
            GetFirstChild()->DeallocateMemory(memoryAllocation.release());
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

    MEMORY_ALLOCATOR_INFO BuddyMemoryAllocator::QueryInfo() const {
        MEMORY_ALLOCATOR_INFO info = mInfo;
        const MEMORY_ALLOCATOR_INFO& memoryInfo = GetFirstChild()->QueryInfo();
        info.UsedMemoryCount = memoryInfo.UsedMemoryCount;
        info.UsedMemoryUsage = memoryInfo.UsedMemoryUsage;
        info.FreeMemoryUsage = memoryInfo.FreeMemoryUsage;
        return info;
    }

    uint64_t BuddyMemoryAllocator::GetBuddyMemorySizeForTesting() const {
        return mPool.GetPoolSize();
    }

}  // namespace gpgmm
