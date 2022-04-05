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

#include "gpgmm/AllocatorNode.h"
#include "gpgmm/BlockAllocator.h"
#include "gpgmm/Error.h"
#include "gpgmm/Memory.h"
#include "gpgmm/MemoryAllocation.h"
#include "gpgmm/WorkerThread.h"
#include "gpgmm/common/Assert.h"
#include "gpgmm/common/Limits.h"

#include <memory>
#include <mutex>

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

        // Total size (in bytes) of free memory.
        uint64_t FreeMemoryUsage;
    };

    class AllocateMemoryTask;

    class MemoryAllocationEvent final : public Event {
      public:
        MemoryAllocationEvent(std::shared_ptr<Event> event,
                              std::shared_ptr<AllocateMemoryTask> task);

        // Event overrides
        void Wait() override;
        bool IsSignaled() override;
        void Signal() override;

        std::unique_ptr<MemoryAllocation> AcquireAllocation() const;

      private:
        std::shared_ptr<AllocateMemoryTask> mTask;
        std::shared_ptr<Event> mEvent;
    };

    class MemoryAllocator : public AllocatorBase, public AllocatorNode<MemoryAllocator> {
      public:
        MemoryAllocator();

        // Constructs a MemoryAllocator that owns a single child allocator.
        explicit MemoryAllocator(std::unique_ptr<MemoryAllocator> child);

        virtual ~MemoryAllocator() = default;

        // Attempts to allocate memory and return a allocation that is at-least of the requested
        // |size| whose value is a multiple of |alignment|. If it cannot, return
        // nullptr. The returned MemoryAllocation is only valid for the lifetime of this allocator.
        // When |neverAllocate| is true, the memory allocator will not allocate anything and
        // effectively no-op.
        // When |cacheSize| is true, the memory allocator may cache for the requested
        // allocation to speed-up subsequent requests of the same size.
        virtual std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t size,
                                                                    uint64_t alignment,
                                                                    bool neverAllocate,
                                                                    bool cacheSize,
                                                                    bool prefetchMemory);

        // Non-blocking version of TryAllocateMemory.
        // Caller must wait for the event to complete before using the resulting allocation.
        std::shared_ptr<MemoryAllocationEvent> TryAllocateMemoryAsync(uint64_t size,
                                                                      uint64_t alignment);

        // Free the allocation by deallocating the block used to sub-allocate it and the underlying
        // memory block used with it. The |allocation| will be considered invalid after
        // DeallocateMemory.
        virtual void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) = 0;

        // Free memory retained by this memory allocator.
        // Used to reuse memory blocks between calls to TryAllocateMemory.
        virtual void ReleaseMemory();

        // If this allocator only allocates memory blocks using the same size, this value
        // must be specified. Otherwise, kInvalidSize is returned to denote any alignment is
        // allowed.
        virtual uint64_t GetMemorySize() const;

        // If this allocator only allocates memory blocks using the same alignment, this value
        // must be specified. Otherwise, kInvalidOffset is returned to denote any alignment is
        // allowed.
        virtual uint64_t GetMemoryAlignment() const;

        // Collect and return the number and size of memory blocks allocated by this allocator.
        // Should be overridden when a child allocator or block allocator is used.
        virtual MEMORY_ALLOCATOR_INFO QueryInfo() const;

      protected:
        // Combine TryAllocateBlock and TryAllocateMemory into a single call so a partial
        // or uninitalized memory allocation cannot be created. If memory cannot be allocated for
        // the block, the block will be deallocated instead of allowing it to leak.
        template <typename GetOrCreateMemoryFn>
        static std::unique_ptr<MemoryAllocation> TrySubAllocateMemory(
            BlockAllocator* allocator,
            uint64_t size,
            uint64_t alignment,
            GetOrCreateMemoryFn&& GetOrCreateMemory) {
            MemoryBlock* block = nullptr;
            GPGMM_TRY_ASSIGN(allocator->TryAllocateBlock(size, alignment), block);

            MemoryBase* memory = GetOrCreateMemory(block);
            if (memory == nullptr) {
                allocator->DeallocateBlock(block);
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

        MEMORY_ALLOCATOR_INFO mInfo = {};

        mutable std::mutex mMutex;
        std::shared_ptr<ThreadPool> mThreadPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_MEMORYALLOCATOR_H_
