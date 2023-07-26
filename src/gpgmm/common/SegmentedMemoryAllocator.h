// Copyright 2022 The GPGMM Authors
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

#ifndef GPGMM_COMMON_SEGMENTEDMEMORYALLOCATOR_H_
#define GPGMM_COMMON_SEGMENTEDMEMORYALLOCATOR_H_

#include "gpgmm/common/LIFOMemoryPool.h"
#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/utils/LinkedList.h"

namespace gpgmm {

    // Represents one or more memory blocks managed in a pool.
    // A memory segment is a node in a linked-list so it may be cached and reuse by the segmented
    // allocator.
    class MemorySegment final : public LIFOMemoryPool, public LinkNode<MemorySegment> {
      public:
        explicit MemorySegment(uint64_t memorySize);
        ~MemorySegment() override;
    };

    // SegmentedMemoryAllocator maintains a sorted segmented list of memory pools to allocate
    // variable-size memory blocks.
    class SegmentedMemoryAllocator : public MemoryAllocatorBase {
      public:
        SegmentedMemoryAllocator(std::unique_ptr<MemoryAllocatorBase> memoryAllocator,
                                 uint64_t memoryAlignment);
        ~SegmentedMemoryAllocator() override;

        // MemoryAllocatorBase interface
        ResultOrError<std::unique_ptr<MemoryAllocation>> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;
        uint64_t ReleaseMemory(uint64_t bytesToRelease = kInvalidSize) override;
        uint64_t GetMemoryAlignment() const override;

        uint64_t GetSegmentSizeForTesting() const;

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(SegmentedMemoryAllocator)

        MemorySegment* GetOrCreateFreeSegment(uint64_t memorySize);

        LinkedList<MemorySegment> mFreeSegments;

        const uint64_t mMemoryAlignment;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_SEGMENTEMEMORYALLOCATOR_H_
