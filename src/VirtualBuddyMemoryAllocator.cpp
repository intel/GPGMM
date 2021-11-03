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

#include "src/VirtualBuddyMemoryAllocator.h"

#include "common/Math.h"

namespace gpgmm {

    VirtualBuddyMemoryAllocator::VirtualBuddyMemoryAllocator(uint64_t maxSystemSize,
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

    VirtualBuddyMemoryAllocator::~VirtualBuddyMemoryAllocator() {
        ASSERT(GetSuballocatedMemorySizeForTesting() == 0);
    }

    uint64_t VirtualBuddyMemoryAllocator::GetMemoryIndex(uint64_t offset) const {
        ASSERT(offset != kInvalidOffset);
        return offset / mMemorySize;
    }

    std::unique_ptr<MemoryAllocation> VirtualBuddyMemoryAllocator::AllocateMemory(
        uint64_t size,
        uint64_t alignment) {
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

        // Avoid tracking all heaps in the buddy system that are not yet allocated.
        const uint64_t memoryIndex = GetMemoryIndex(block->mOffset);
        if (memoryIndex >= mMemoryAllocations.size()) {
            mMemoryAllocations.resize(memoryIndex + 1);
        }

        if (mMemoryAllocations[memoryIndex] == nullptr) {
            // Transfer ownership to this allocator
            std::unique_ptr<MemoryAllocation> allocation =
                mMemoryAllocator->AllocateMemory(mMemorySize, mMemoryAlignment);
            if (allocation == nullptr) {
                return nullptr;
            }
            mMemoryAllocations[memoryIndex] = std::move(allocation);
        }

        AddSubAllocatedRef(mMemoryAllocations[memoryIndex].get());

        AllocationInfo info;
        info.mBlock = block;
        info.mMethod = AllocationMethod::kSubAllocated;

        // Allocation offset is always local to the memory.
        const uint64_t memoryOffset = block->mOffset % mMemorySize;

        return std::make_unique<MemoryAllocation>(/*allocator*/ this, info, memoryOffset,
                                                  mMemoryAllocations[memoryIndex]->GetMemory());
    }

    void VirtualBuddyMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        ASSERT(allocation != nullptr);

        const AllocationInfo info = allocation->GetInfo();

        ASSERT(info.mMethod == AllocationMethod::kSubAllocated);

        const uint64_t memoryIndex = GetMemoryIndex(info.mBlock->mOffset);

        ASSERT(mMemoryAllocations[memoryIndex] != nullptr);
        ReleaseSubAllocatedRef(mMemoryAllocations[memoryIndex].get());

        if (!IsSubAllocated(*mMemoryAllocations[memoryIndex])) {
            mMemoryAllocator->DeallocateMemory(mMemoryAllocations[memoryIndex].release());
        }

        mBuddyBlockAllocator.DeallocateBlock(info.mBlock);
    }

    uint64_t VirtualBuddyMemoryAllocator::GetMemorySize() const {
        return mMemorySize;
    }

    uint64_t VirtualBuddyMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAllocator->GetMemoryAlignment();
    }

    uint64_t VirtualBuddyMemoryAllocator::GetSuballocatedMemorySizeForTesting() const {
        uint64_t count = 0;
        for (auto& allocation : mMemoryAllocations) {
            if (allocation != nullptr) {
                count++;
            }
        }
        return count;
    }

}  // namespace gpgmm
