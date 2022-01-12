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

#ifndef GPGMM_MEMORYALLOCATOR_H_
#define GPGMM_MEMORYALLOCATOR_H_

#include "gpgmm/BlockAllocator.h"
#include "gpgmm/Memory.h"
#include "gpgmm/MemoryAllocation.h"
#include "gpgmm/common/Assert.h"
#include "gpgmm/common/Limits.h"

#include <memory>

namespace gpgmm {

    struct MEMORY_ALLOCATOR_INFO {
        // Number of used sub-allocated blocks within the same memory.
        uint32_t UsedBlockCount;

        // Total size (in bytes) of used sub-allocated blocks.
        uint64_t UsedBlockUsage;

        // Number of used memory allocations.
        uint32_t UsedMemoryCount;

        // Total size (in bytes) of used memory.
        uint64_t UsedMemoryUsage;
    };

    class MemoryAllocator : public AllocatorBase {
      public:
        virtual ~MemoryAllocator() = default;

        // Attempts to allocate and return a memory allocation that is at-least of the requested
        // |size| that's also sized-aligned or a multiple of |alignment|. If not, return nullptr
        // instead. The returned MemoryAllocation is only valid for the lifetime of this allocator.
        virtual std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t size,
                                                                    uint64_t alignment,
                                                                    bool neverAllocate) = 0;

        // Free the allocation by deallocating the block used to sub-allocate it and the underlying
        // memory block used with it. The |allocation| will be considered invalid after
        // DeallocateMemory.
        virtual void DeallocateMemory(MemoryAllocation* allocation) = 0;

        // Free memory retained by this memory allocator.
        // Used to reuse memory blocks between calls to TryAllocateMemory.
        virtual void ReleaseMemory() {
        }

        // Return the fixed-size or alignment of this memory allocator. If the parent allocator
        // always calls TryAllocateMemory with the same memory |size| and |alignment|, they do not
        // need to be overridden by the child allocator.
        virtual uint64_t GetMemorySize() const;
        virtual uint64_t GetMemoryAlignment() const;

        // Collect and return the number and size of memory blocks allocated by this allocator.
        // Will be overridden if a nested allocator or a seperate block allocator is used.
        virtual MEMORY_ALLOCATOR_INFO QueryInfo() const {
            return mStats;
        }

      protected:
        // Combine AllocateBlock and TryAllocateMemory into a single call so a partial
        // or uninitalized memory allocation cannot be created. If memory cannot be allocated for
        // the block, the block will be deallocated instead of allowing it to leak.
        template <typename GetOrCreateMemoryFn>
        std::unique_ptr<MemoryAllocation> TrySubAllocateMemory(
            BlockAllocator* blockAllocator,
            uint64_t blockSize,
            uint64_t blockAlignment,
            GetOrCreateMemoryFn&& GetOrCreateMemory) {
            Block* block = blockAllocator->AllocateBlock(blockSize, blockAlignment);
            if (block == nullptr) {
                return nullptr;
            }

            MemoryBase* memory = GetOrCreateMemory(block);
            if (memory == nullptr) {
                blockAllocator->DeallocateBlock(block);
                return nullptr;
            }

            ASSERT(memory != nullptr);
            memory->Ref();

            // Calling memory allocator must be responsible in fully initializing the memory
            // allocation. This is because we do not yet know how to map the sub-allocated block to
            // memory.
            return std::make_unique<MemoryAllocation>(nullptr, memory, kInvalidOffset,
                                                      AllocationMethod::kUndefined, block);
        }

        MEMORY_ALLOCATOR_INFO mStats = {};
    };

}  // namespace gpgmm

#endif  // GPGMM_MEMORYALLOCATOR_H_
