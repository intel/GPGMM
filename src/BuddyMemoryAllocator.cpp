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

#include "src/ResourceMemoryAllocator.h"
#include "src/common/Math.h"

namespace gpgmm {

    BuddyMemoryAllocator::BuddyMemoryAllocator(uint64_t maxSystemSize,
                                               uint64_t memoryBlockSize,
                                               ResourceMemoryAllocator* memoryAllocator)
        : mMemoryBlockSize(memoryBlockSize),
          mBuddyBlockAllocator(maxSystemSize),
          mMemoryAllocator(memoryAllocator) {
        ASSERT(memoryBlockSize <= maxSystemSize);
        ASSERT(IsPowerOfTwo(mMemoryBlockSize));
        ASSERT(maxSystemSize % mMemoryBlockSize == 0);

        mTrackedSubAllocations.resize(maxSystemSize / mMemoryBlockSize);
    }

    void BuddyMemoryAllocator::Release() {
        mMemoryAllocator->Release();
        mTrackedSubAllocations.clear();
    }

    uint64_t BuddyMemoryAllocator::GetMemoryIndex(uint64_t offset) const {
        ASSERT(offset != kInvalidOffset);
        return offset / mMemoryBlockSize;
    }

    ResourceMemoryAllocation BuddyMemoryAllocator::Allocate(uint64_t size, uint64_t alignment) {
        if (size == 0) {
            return GPGMM_INVALID_ALLOCATION;
        }

        // Check the unaligned size to avoid overflowing NextPowerOfTwo.
        if (size > mMemoryBlockSize) {
            return GPGMM_INVALID_ALLOCATION;
        }

        // Round allocation size to nearest power-of-two.
        size = NextPowerOfTwo(size);

        // Allocation cannot exceed the memory size.
        if (size > mMemoryBlockSize) {
            return GPGMM_INVALID_ALLOCATION;
        }

        // Attempt to sub-allocate a block of the requested size.
        const uint64_t blockOffset = mBuddyBlockAllocator.Allocate(size, alignment);
        if (blockOffset == kInvalidOffset) {
            return GPGMM_INVALID_ALLOCATION;
        }

        const uint64_t memoryIndex = GetMemoryIndex(blockOffset);
        if (mTrackedSubAllocations[memoryIndex].refcount == 0) {
            // Transfer ownership to this allocator
            ResourceMemoryAllocation memory = mMemoryAllocator->Allocate(mMemoryBlockSize);
            if (memory.GetResourceMemory() == nullptr) {
                return GPGMM_INVALID_ALLOCATION;
            }
            mTrackedSubAllocations[memoryIndex] = {/*refcount*/ 0, std::move(memory)};
        }

        mTrackedSubAllocations[memoryIndex].refcount++;

        AllocationInfo info;
        info.mBlockOffset = blockOffset;
        info.mMethod = AllocationMethod::kSubAllocated;

        // Allocation offset is always local to the memory.
        const uint64_t memoryOffset = blockOffset % mMemoryBlockSize;

        return ResourceMemoryAllocation{
            mTrackedSubAllocations[memoryIndex].mMemoryAllocation.GetAllocator(), info,
            memoryOffset,
            mTrackedSubAllocations[memoryIndex].mMemoryAllocation.GetResourceMemory()};
    }

    void BuddyMemoryAllocator::Deallocate(const ResourceMemoryAllocation& allocation) {
        const AllocationInfo info = allocation.GetInfo();

        ASSERT(info.mMethod == AllocationMethod::kSubAllocated);

        const uint64_t memoryIndex = GetMemoryIndex(info.mBlockOffset);

        ASSERT(mTrackedSubAllocations[memoryIndex].refcount > 0);
        mTrackedSubAllocations[memoryIndex].refcount--;

        if (mTrackedSubAllocations[memoryIndex].refcount == 0) {
            mMemoryAllocator->Deallocate(mTrackedSubAllocations[memoryIndex].mMemoryAllocation);
        }

        mBuddyBlockAllocator.Deallocate(info.mBlockOffset);
    }

    uint64_t BuddyMemoryAllocator::GetMemoryBlockSize() const {
        return mMemoryBlockSize;
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
