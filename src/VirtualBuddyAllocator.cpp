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

#include "src/VirtualBuddyAllocator.h"

#include "src/common/Math.h"

namespace gpgmm {

    VirtualBuddyAllocator::VirtualBuddyAllocator(uint64_t maxSystemSize,
                                                 MemoryAllocator* memoryAllocator)
        : mMemoryAllocator(memoryAllocator),
          mMemorySize(mMemoryAllocator->GetMemorySize()),
          mBuddyBlockAllocator(maxSystemSize) {
        ASSERT(mMemorySize <= maxSystemSize);
        ASSERT(IsPowerOfTwo(mMemorySize));
        ASSERT(maxSystemSize % mMemorySize == 0);
    }

    VirtualBuddyAllocator::~VirtualBuddyAllocator() {
        ASSERT(GetPoolSizeForTesting() == 0);
    }

    void VirtualBuddyAllocator::Release() {
        mMemoryAllocator->Release();
    }

    uint64_t VirtualBuddyAllocator::GetMemoryIndex(uint64_t offset) const {
        ASSERT(offset != kInvalidOffset);
        return offset / mMemorySize;
    }

    void VirtualBuddyAllocator::SubAllocate(uint64_t size,
                                            uint64_t alignment,
                                            MemoryAllocation& allocation) {
        if (size == 0) {
            return;
        }

        // Check the unaligned size to avoid overflowing NextPowerOfTwo.
        if (size > mMemorySize) {
            return;
        }

        // Round allocation size to nearest power-of-two.
        size = NextPowerOfTwo(size);

        // Allocation cannot exceed the memory size.
        if (size > mMemorySize) {
            return;
        }

        // Attempt to sub-allocate a block of the requested size.
        const uint64_t blockOffset = mBuddyBlockAllocator.Allocate(size, alignment);
        if (blockOffset == kInvalidOffset) {
            return;
        }

        // Avoid tracking all heaps in the buddy system that are not yet allocated.
        const uint64_t memoryIndex = GetMemoryIndex(blockOffset);
        if (memoryIndex >= mMemoryAllocations.size()) {
            mMemoryAllocations.resize(memoryIndex + 1);
        }

        if (!IsSubAllocated(mMemoryAllocations[memoryIndex])) {
            // Transfer ownership to this allocator
            MemoryAllocation memoryAllocation;
            mMemoryAllocator->AllocateMemory(/*inout*/ memoryAllocation);
            if (memoryAllocation == GPGMM_INVALID_ALLOCATION) {
                return;
            }
            mMemoryAllocations[memoryIndex] = std::move(memoryAllocation);
        }

        IncrementSubAllocatedRef(mMemoryAllocations[memoryIndex]);

        AllocationInfo info;
        info.mBlockOffset = blockOffset;
        info.mMethod = AllocationMethod::kSubAllocated;

        // Allocation offset is always local to the memory.
        const uint64_t memoryOffset = blockOffset % mMemorySize;

        allocation = MemoryAllocation{mMemoryAllocations[memoryIndex].GetAllocator(), info,
                                      memoryOffset, mMemoryAllocations[memoryIndex].GetMemory()};
    }

    void VirtualBuddyAllocator::AllocateMemory(MemoryAllocation& allocation) {
        // Must sub-allocate, cannot allocate memory directly.
        UNREACHABLE();
    }

    void VirtualBuddyAllocator::DeallocateMemory(MemoryAllocation& allocation) {
        const AllocationInfo info = allocation.GetInfo();

        ASSERT(info.mMethod == AllocationMethod::kSubAllocated);

        const uint64_t memoryIndex = GetMemoryIndex(info.mBlockOffset);
        DecrementSubAllocatedRef(mMemoryAllocations[memoryIndex]);

        if (!IsSubAllocated(mMemoryAllocations[memoryIndex])) {
            mMemoryAllocator->DeallocateMemory(mMemoryAllocations[memoryIndex]);
        }

        mBuddyBlockAllocator.Deallocate(info.mBlockOffset);
    }

    uint64_t VirtualBuddyAllocator::GetMemorySize() const {
        return mMemorySize;
    }

    uint64_t VirtualBuddyAllocator::GetMemoryAlignment() const {
        return mMemoryAllocator->GetMemoryAlignment();
    }

    uint64_t VirtualBuddyAllocator::GetPoolSizeForTesting() const {
        uint64_t count = 0;
        for (const MemoryAllocation& allocation : mMemoryAllocations) {
            if (IsSubAllocated(allocation)) {
                count++;
            }
        }
        return count;
    }

}  // namespace gpgmm
