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

#ifndef GPGMM_SEGMENTEDMEMORYALLOCATOR_H_
#define GPGMM_SEGMENTEDMEMORYALLOCATOR_H_

#include "common/LinkedList.h"
#include "src/MemoryAllocator.h"

namespace gpgmm {

    class MemoryPool;

    // Represents one or more memory blocks managed in a pool.
    // A memory segment is a node in a linked-list so it may be cached and reuse by the segmented
    // allocator.
    class MemorySegment : public LinkNode<MemorySegment> {
      public:
        MemorySegment(uint64_t memorySize, std::unique_ptr<MemoryPool> pool);
        virtual ~MemorySegment();

        // Return the size of the memory segment which is defined as the size of any memory block in
        // the pool. The size is used to lookup a free memory block in a segment.
        uint64_t GetSize() const;

        // Return the pool managed by this segment.
        MemoryPool* GetPool() const;

      private:
        const uint64_t mMemorySize;
        std::unique_ptr<MemoryPool> mPool;
    };

    // SegmentedMemoryAllocator maintains a sorted segmented list of memory pools to allocate
    // variable-size memory blocks.
    class SegmentedMemoryAllocator : public MemoryAllocator {
      public:
        SegmentedMemoryAllocator(MemoryAllocator* memoryAllocator, uint64_t memoryAlignment);
        ~SegmentedMemoryAllocator() override;

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t size,
                                                            uint64_t alignment,
                                                            bool neverAllocate) override;
        void DeallocateMemory(MemoryAllocation* allocation) override;
        void ReleaseMemory() override;

        uint64_t GetPoolSizeForTesting() const;

      private:
        MemorySegment* GetOrCreateFreeSegment(uint64_t memorySize);

        MemoryAllocator* const mMemoryAllocator;

        LinkedList<MemorySegment> mFreeSegments;

        const uint64_t mMemoryAlignment;
    };

}  // namespace gpgmm

#endif  // GPGMM_SEGMENTEMEMORYALLOCATOR_H_
