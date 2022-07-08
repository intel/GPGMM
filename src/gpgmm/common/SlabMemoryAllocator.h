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

#ifndef GPGMM_COMMON_SLABMEMORYALLOCATOR_H_
#define GPGMM_COMMON_SLABMEMORYALLOCATOR_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/MemoryCache.h"
#include "gpgmm/common/SlabBlockAllocator.h"
#include "gpgmm/utils/LinkedList.h"
#include "gpgmm/utils/Math.h"

#include <vector>

namespace gpgmm {

    // SlabMemoryAllocator uses the slab allocation technique to sub-allocate slabs of device
    // memory. Unlike other allocators, the slab allocator eliminates memory fragmentation caused by
    // frequent allocation and de-allocations and always services requests in constant-time. The
    // main draw-back of slab allocation is the complexity to support variable-sized allocations
    // (i.e. size is not known at compile-time).
    //
    // Internally, the slab allocator manages a binary cache of slabs up to |maxSlabSize| where
    // each slab allocates fixed-size |blockSize| blocks in contigious memory. A slab can be in
    // either one of two states, free or full. A "free slab" means at-least one block exists to be
    // allocated. A "full" slab means ALL blocks are allocated in the slab. This ensures a freely
    // available slab can be quickly allocated without a search. To de-allocate, the same slab is
    // cached on the block which is used to release the underlying slab memory once the last block
    // is de-allocated.
    //
    // Slab allocator implementation is closely based on Jeff Bonwick's paper "The Slab Allocator".
    // https://people.eecs.berkeley.edu/~kubitron/courses/cs194-24-S13/hand-outs/bonwick_slab.pdf
    //
    class SlabMemoryAllocator final : public MemoryAllocator {
      public:
        SlabMemoryAllocator(uint64_t blockSize,
                            uint64_t maxSlabSize,
                            uint64_t minSlabSize,
                            uint64_t slabAlignment,
                            double slabFragmentationLimit,
                            bool allowSlabPrefetch,
                            double slabGrowthFactor,
                            MemoryAllocator* memoryAllocator);
        ~SlabMemoryAllocator() override;

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        MemoryAllocatorInfo GetInfo() const override;

        const char* GetTypename() const override;

      private:
        uint64_t ComputeSlabSize(uint64_t requestSize,
                                 uint64_t baseSlabSize,
                                 uint64_t availableForAllocation) const;

        uint64_t FindNextFreeSlabOfSize(uint64_t slabSize) const;

        bool IsPrefetchCoverageBelowThreshold() const;

        // Group of one or more slabs of the same size.
        struct SlabCache {
            SizedLinkedList<Slab> FreeList;  // Slabs that contain partial or empty
                                             // slabs or some free blocks.
            SizedLinkedList<Slab> FullList;  // Slabs that are full or all blocks
                                             // are marked as used.
        };

        SlabCache* GetOrCreateCache(uint64_t slabSize);

        std::vector<SlabCache> mCaches;

        uint64_t mLastUsedSlabSize = 0;

        const uint64_t mBlockSize;
        const uint64_t mSlabAlignment;
        const uint64_t mMaxSlabSize;
        const uint64_t mMinSlabSize;  // Optional size when non-zero.

        const double mSlabFragmentationLimit;
        const bool mAllowSlabPrefetch;
        const double mSlabGrowthFactor;

        MemoryAllocator* mMemoryAllocator = nullptr;
        std::shared_ptr<MemoryAllocationEvent> mNextSlabAllocationEvent;
    };

    // SlabCacheAllocator slab-allocates |minBlockSize|-size aligned allocations from
    // fixed-sized slabs.
    class SlabCacheAllocator : public MemoryAllocator {
      public:
        SlabCacheAllocator(uint64_t maxSlabSize,
                           uint64_t minSlabSize,
                           uint64_t slabAlignment,
                           double slabFragmentationLimit,
                           bool allowSlabPrefetch,
                           double slabGrowthFactor,
                           std::unique_ptr<MemoryAllocator> memoryAllocator);

        ~SlabCacheAllocator() override;

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        MemoryAllocatorInfo GetInfo() const override;

        uint64_t GetMemorySize() const override;

      private:
        const char* GetTypename() const override;

        class SlabAllocatorCacheEntry : public NonCopyable {
          public:
            explicit SlabAllocatorCacheEntry(uint64_t blockSize) : mBlockSize(blockSize) {
            }

            uint64_t GetKey() const {
                return mBlockSize;
            }

            SlabMemoryAllocator* pSlabAllocator = nullptr;

          private:
            const uint64_t mBlockSize;
        };

        const uint64_t mMaxSlabSize;
        const uint64_t mMinSlabSize;
        const uint64_t mSlabAlignment;

        const double mSlabFragmentationLimit;
        const bool mAllowSlabPrefetch;
        const double mSlabGrowthFactor;

        LinkedList<MemoryAllocator> mSlabAllocators;
        MemoryCache<SlabAllocatorCacheEntry> mSizeCache;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_SLABMEMORYALLOCATOR_H_
