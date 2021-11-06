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

#include "src/BuddyMemoryAllocator.h"

#include "common/Math.h"

namespace gpgmm {

    BuddyMemoryAllocator::BuddyMemoryAllocator(uint64_t maxSystemSize,
                                               uint64_t memorySize,
                                               uint64_t memoryAlignment,
                                               MemoryAllocator* memoryAllocator)
        : mMemoryAllocator(memoryAllocator),
          mMemorySize(memorySize),
          mMemoryAlignment(memoryAlignment),
          mBuddyBlockAllocator(maxSystemSize) {
        ASSERT(mMemorySize <= maxSystemSize);
        ASSERT(IsPowerOfTwo(mMemorySize));
        ASSERT(maxSystemSize % mMemorySize == 0);
    }

    BuddyMemoryAllocator::~BuddyMemoryAllocator() {
        ASSERT(mPool.GetPoolSize() == 0);
    }

    uint64_t BuddyMemoryAllocator::GetMemoryIndex(uint64_t offset) const {
        ASSERT(offset != kInvalidOffset);
        return offset / mMemorySize;
    }

    std::unique_ptr<MemoryAllocation> BuddyMemoryAllocator::AllocateMemory(uint64_t size,
                                                                           uint64_t alignment,
                                                                           bool neverAllocate) {
        if (size == 0) {
            return nullptr;
        }

        // Check the unaligned size to avoid overflowing NextPowerOfTwo.
        if (size > mMemorySize) {
            return nullptr;
        }

        // Round allocation size to nearest power-of-two.
        size = NextPowerOfTwo(size);

        // Allocation cannot exceed the memory size.
        if (size > mMemorySize) {
            return nullptr;
        }

        // Attempt to sub-allocate a block of the requested size.
        Block* block = mBuddyBlockAllocator.AllocateBlock(size, alignment);
        if (block == nullptr) {
            return nullptr;
        }

        const uint64_t memoryIndex = GetMemoryIndex(block->Offset);
        std::unique_ptr<MemoryAllocation> memoryAllocation = mPool.AcquireFromPool(memoryIndex);

        if (memoryAllocation == nullptr) {
            memoryAllocation =
                mMemoryAllocator->AllocateMemory(mMemorySize, mMemoryAlignment, neverAllocate);
            if (memoryAllocation == nullptr) {
                return nullptr;
            }
        }

        AddSubAllocatedRef(memoryAllocation.get());

        MemoryBase* memory = memoryAllocation->GetMemory();
        mPool.ReturnToPool(std::move(memoryAllocation), memoryIndex);

        AllocationInfo info;
        info.Block = block;
        info.Method = AllocationMethod::kSubAllocated;

        // Allocation offset is always local to the memory.
        const uint64_t memoryOffset = block->Offset % mMemorySize;

        return std::make_unique<MemoryAllocation>(/*allocator*/ this, info, memoryOffset, memory);
    }

    void BuddyMemoryAllocator::DeallocateMemory(MemoryAllocation* subAllocation) {
        ASSERT(subAllocation != nullptr);

        const AllocationInfo info = subAllocation->GetInfo();

        ASSERT(info.Method == AllocationMethod::kSubAllocated);

        const uint64_t memoryIndex = GetMemoryIndex(info.Block->Offset);

        mBuddyBlockAllocator.DeallocateBlock(info.Block);

        std::unique_ptr<MemoryAllocation> memoryAllocation = mPool.AcquireFromPool(memoryIndex);

        ReleaseSubAllocatedRef(memoryAllocation.get());

        if (!IsSubAllocated(*memoryAllocation)) {
            mMemoryAllocator->DeallocateMemory(memoryAllocation.release());
        } else {
            mPool.ReturnToPool(std::move(memoryAllocation), memoryIndex);
        }
    }

    uint64_t BuddyMemoryAllocator::GetMemorySize() const {
        return mMemorySize;
    }

    uint64_t BuddyMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAllocator->GetMemoryAlignment();
    }

    uint64_t BuddyMemoryAllocator::GetPoolSizeForTesting() const {
        return mPool.GetPoolSize();
    }

}  // namespace gpgmm
