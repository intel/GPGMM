// Copyright 2019 The Dawn Authors
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

#include "src/MemoryAllocator.h"
#include "src/common/Math.h"

namespace gpgmm {

    BuddyMemoryAllocator::BuddyMemoryAllocator(uint64_t maxSystemSize,
                                               MemoryAllocator* memoryAllocator)
        : mMemoryAllocator(memoryAllocator),
          mMemorySize(mMemoryAllocator->GetMemorySize()),
          mBuddyBlockAllocator(maxSystemSize) {
        ASSERT(mMemorySize <= maxSystemSize);
        ASSERT(IsPowerOfTwo(mMemorySize));
        ASSERT(maxSystemSize % mMemorySize == 0);

        mTrackedSubAllocations.resize(maxSystemSize / mMemorySize);
    }

    void BuddyMemoryAllocator::Release() {
        ASSERT(ComputeTotalNumOfHeapsForTesting() == 0);

        mTrackedSubAllocations.clear();
        mMemoryAllocator->Release();
    }

    uint64_t BuddyMemoryAllocator::GetMemoryIndex(uint64_t offset) const {
        ASSERT(offset != kInvalidOffset);
        return offset / mMemorySize;
    }

    void BuddyMemoryAllocator::SubAllocate(uint64_t size,
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

        const uint64_t memoryIndex = GetMemoryIndex(blockOffset);
        if (mTrackedSubAllocations[memoryIndex].refcount == 0) {
            // Transfer ownership to this allocator
            MemoryAllocation memoryAllocation;
            mMemoryAllocator->AllocateMemory(/*inout*/ memoryAllocation);
            if (memoryAllocation == GPGMM_INVALID_ALLOCATION) {
                return;
            }
            mTrackedSubAllocations[memoryIndex] = {/*refcount*/ 0, std::move(memoryAllocation)};
        }

        mTrackedSubAllocations[memoryIndex].refcount++;

        AllocationInfo info;
        info.mBlockOffset = blockOffset;
        info.mMethod = AllocationMethod::kSubAllocated;

        // Allocation offset is always local to the memory.
        const uint64_t memoryOffset = blockOffset % mMemorySize;

        allocation = MemoryAllocation{
            mTrackedSubAllocations[memoryIndex].mMemoryAllocation.GetAllocator(), info,
            memoryOffset, mTrackedSubAllocations[memoryIndex].mMemoryAllocation.GetMemory()};
    }

    void BuddyMemoryAllocator::AllocateMemory(MemoryAllocation& allocation) {
        // Must sub-allocate, cannot allocate memory directly.
        UNREACHABLE();
    }

    void BuddyMemoryAllocator::DeallocateMemory(MemoryAllocation& allocation) {
        const AllocationInfo info = allocation.GetInfo();

        ASSERT(info.mMethod == AllocationMethod::kSubAllocated);

        const uint64_t memoryIndex = GetMemoryIndex(info.mBlockOffset);

        ASSERT(mTrackedSubAllocations[memoryIndex].refcount > 0);
        mTrackedSubAllocations[memoryIndex].refcount--;

        if (mTrackedSubAllocations[memoryIndex].refcount == 0) {
            mMemoryAllocator->DeallocateMemory(mTrackedSubAllocations[memoryIndex].mMemoryAllocation);
        }

        mBuddyBlockAllocator.Deallocate(info.mBlockOffset);
    }

    uint64_t BuddyMemoryAllocator::GetMemorySize() const {
        return mMemorySize;
    }

    uint64_t BuddyMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAllocator->GetMemoryAlignment();
    }

    uint64_t BuddyMemoryAllocator::ComputeTotalNumOfHeapsForTesting() const {
        uint64_t count = 0;
        for (const TrackedSubAllocations& allocation : mTrackedSubAllocations) {
            if (allocation.refcount > 0) {
                count++;
            }
        }
        return count;
    }

}  // namespace gpgmm
