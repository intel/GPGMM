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

#ifndef GPGMM_COMMON_MEMORYALLOCATOR_H_
#define GPGMM_COMMON_MEMORYALLOCATOR_H_

#include "gpgmm/common/AllocatorNode.h"
#include "gpgmm/common/BlockAllocator.h"
#include "gpgmm/common/Error.h"
#include "gpgmm/common/Memory.h"
#include "gpgmm/common/MemoryAllocation.h"
#include "gpgmm/common/WorkerThread.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/Log.h"

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

        MEMORY_ALLOCATOR_INFO& operator+=(const MEMORY_ALLOCATOR_INFO& rhs) {
            UsedBlockCount += rhs.UsedBlockCount;
            UsedBlockUsage += rhs.UsedBlockUsage;
            FreeMemoryUsage += rhs.FreeMemoryUsage;
            UsedMemoryUsage += rhs.UsedMemoryUsage;
            UsedMemoryCount += rhs.UsedMemoryCount;
            return *this;
        }
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

    /** \struct MEMORY_ALLOCATION_REQUEST
    Describes a request to allocate memory.
    */
    struct MEMORY_ALLOCATION_REQUEST {
        /** \brief Request the size, in bytes, of the allocation.

        Actual allocated size might be larger due to allocator constraints.
        */
        uint64_t SizeInBytes;

        /** \brief Requested alignment, in bytes, of the allocation.

        This is the alignment value of the memory block, which is not necessarily a multiple of the
        allocated size. For example, a 128-byte alignment means the memory block offset must
        be a multiple of 128. But the block size may only be 64 bytes, leaving the other 64 bytes
        allocated but unused.
        */
        uint64_t Alignment;

        /** \brief Request to never create underlying memory.

        Used to check whether or not the memory allocation could succeed, without requiring actual
        memory to be created. Or used to ensure the requested allocation memory ONLY comes from the
        existing "working set" of memory (eg. pool), created by previous allocations.
        */
        bool NeverAllocate;

        /** \brief Request to additionally cache for the allocated size, to speed-up subsequent
        requests of the same request size.
        */
        bool AlwaysCacheSize;

        /** \brief Request to pre-fetch the next memory block needed for a subsquent request based
        on the requested size.
        */
        bool AlwaysPrefetch;

        /** \brief Memory available for the allocation.

        A value of 0 means there is no memory available left to allocate from.
        */
        uint64_t AvailableForAllocation;
    };

    class MemoryAllocator : public AllocatorBase, public AllocatorNode<MemoryAllocator> {
      public:
        MemoryAllocator();

        // Constructs a MemoryAllocator that owns a single child allocator.
        explicit MemoryAllocator(std::unique_ptr<MemoryAllocator> next);

        virtual ~MemoryAllocator() override;

        // Attempts to allocate memory and return an allocation that has at-least
        // |requestedSize| allocated space whose value is a multiple of |alignment|. If it cannot,
        // return nullptr. The returned allocation is only valid for the lifetime of |this|
        // allocator.
        virtual std::unique_ptr<MemoryAllocation> TryAllocateMemory(
            const MEMORY_ALLOCATION_REQUEST& request);

        // Non-blocking version of TryAllocateMemory.
        // Caller must wait for the event to complete before using the resulting allocation.
        std::shared_ptr<MemoryAllocationEvent> TryAllocateMemoryAsync(
            const MEMORY_ALLOCATION_REQUEST& request);

        // Free the allocation by deallocating the block used to sub-allocate it and the underlying
        // memory block used with it. Caller must assume |allocation| is invalid after
        // DeallocateMemory gets called.
        virtual void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) = 0;

        // Free memory retained by |this| memory allocator.
        // Used to reuse memory between calls to TryAllocateMemory.
        virtual uint64_t ReleaseMemory(uint64_t bytesToRelease = kInvalidSize);

        // Get the fixed-memory sized of |this| memory allocator.
        // If this allocator only allocates memory blocks using the same size, this value
        // is guarenteed to valid. Otherwise, kInvalidSize is returned to denote any memory size
        // could be created by |this| allocator.
        virtual uint64_t GetMemorySize() const;

        // Get the fixed-memory alignment of |this| memory allocator.
        // If this allocator only allocates memory using the same alignment, this value
        // is guarenteed to valid. Otherwise, kInvalidOffset is returned to denote any alignment is
        // allowed.
        virtual uint64_t GetMemoryAlignment() const;

        // Get memory allocator usage.
        // Should be overridden when a child or block allocator is used to avoid
        // over-counting.
        virtual MEMORY_ALLOCATOR_INFO GetInfo() const;

        const char* GetTypename() const override;

      protected:
        // Combine TryAllocateBlock and TryAllocateMemory into a single call so a partial
        // or uninitalized memory allocation cannot be created. If memory cannot be allocated for
        // the block, the block will be deallocated instead of allowing it to leak.
        template <typename GetOrCreateMemoryFn>
        static std::unique_ptr<MemoryAllocation> TrySubAllocateMemory(
            BlockAllocator* allocator,
            uint64_t requestSize,
            uint64_t alignment,
            GetOrCreateMemoryFn&& GetOrCreateMemory) {
            MemoryBlock* block = nullptr;
            GPGMM_TRY_ASSIGN(allocator->TryAllocateBlock(requestSize, alignment), block);

            MemoryBase* memory = GetOrCreateMemory(block);
            if (memory == nullptr) {
                DebugLog() << std::string(allocator->GetTypename()) +
                                  " failed to sub-allocate memory range = ["
                           << std::to_string(block->Offset) << ", "
                           << std::to_string(block->Offset + block->Size) << ").";
                allocator->DeallocateBlock(block);
                return nullptr;
            }

            ASSERT(memory != nullptr);
            memory->Ref();

            // Caller is be responsible in fully initializing the memory allocation.
            // This is because TrySubAllocateMemory() does not necessarily know how to map the
            // final sub-allocated block to created memory.
            return std::make_unique<MemoryAllocation>(nullptr, memory, kInvalidOffset,
                                                      AllocationMethod::kUndefined, block);
        }

        MEMORY_ALLOCATOR_INFO mInfo = {};

        mutable std::mutex mMutex;
        std::shared_ptr<ThreadPool> mThreadPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORYALLOCATOR_H_