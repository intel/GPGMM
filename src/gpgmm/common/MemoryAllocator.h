// Copyright 2019 The Dawn Authors
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

#ifndef SRC_GPGMM_COMMON_MEMORYALLOCATOR_H_
#define SRC_GPGMM_COMMON_MEMORYALLOCATOR_H_

#include "gpgmm/common/BlockAllocator.h"
#include "gpgmm/common/Error.h"
#include "gpgmm/common/Memory.h"
#include "gpgmm/common/MemoryAllocation.h"
#include "gpgmm/common/ThreadPool.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/LinkedList.h"
#include "gpgmm/utils/Log.h"
#include "gpgmm/utils/Refcount.h"

#include <memory>
#include <mutex>

namespace gpgmm {

    class AllocateMemoryTask;

    // Event used to notify caller when AllocateMemoryTask has completed.
    class MemoryAllocationEvent final : public Event {
      public:
        MemoryAllocationEvent(std::shared_ptr<Event> event,
                              std::shared_ptr<AllocateMemoryTask> task);

        // Event overrides
        void Wait() override;

        ResultOrError<std::unique_ptr<MemoryAllocationBase>> AcquireAllocation() const;

      private:
        void Signal() override;
        bool IsSignaled() override;

        std::shared_ptr<AllocateMemoryTask> mTask;
        std::shared_ptr<Event> mEvent;
    };

    struct MemoryAllocationRequest {
        // Request the size, in bytes, of the allocation.
        uint64_t SizeInBytes;

        // Requested alignment, in bytes, of the allocation.
        //
        // This is the alignment value of the memory block, which is not necessarily a multiple of
        // the allocated size. For example, a 128-byte alignment means the memory block offset must
        // be a multiple of 128. But the block size may only be 64 bytes, leaving the other 64 bytes
        // allocated but unused.
        uint64_t Alignment;

        // Request to never create underlying memory.
        //
        // Used to check whether or not the memory allocation could succeed, without requiring
        // actual memory to be created. Or used to ensure the requested allocation memory ONLY comes
        // from the existing "working set" of memory (eg. pool), created by previous allocations.
        bool NeverAllocate;

        // Request to additionally cache for the allocated size, to speed-up subsequent
        // requests of the same request size.
        bool AlwaysCacheSize;

        // Request to pre-fetch the next memory block needed for a subsquent request based
        // on the requested size.
        bool AlwaysPrefetch;

        // Memory available for the allocation.
        // A value of 0 means there is no memory available left to allocate from.
        uint64_t AvailableForAllocation;
    };

    // Additional information about the memory allocator usage.
    struct MemoryAllocatorStats {
        // Number of used sub-allocated blocks within the same memory.
        uint32_t UsedBlockCount;

        // Total size, in bytes, of used sub-allocated blocks.
        uint64_t UsedBlockUsage;

        // Number of used memory allocations.
        uint32_t UsedMemoryCount;

        // Total size, in bytes, of used memory.
        uint64_t UsedMemoryUsage;

        // Total size, in bytes, of free memory.
        uint64_t FreeMemoryUsage;

        // Cache misses not eliminated by prefetching.
        uint64_t PrefetchedMemoryMisses;

        // Cache misses eliminated because of prefetching.
        uint64_t PrefetchedMemoryMissesEliminated;

        // Requested size was NOT cached.
        uint64_t SizeCacheMisses;

        // Requested size was cached.
        uint64_t SizeCacheHits;

        // Adds or sums together stats.
        MemoryAllocatorStats& operator+=(const MemoryAllocatorStats& rhs);
    };

    // Amount of memory, expressed as a percentage of memory, that is acceptable to waste
    // to fragmentation. For example, a 6 byte request may require 8 bytes (eg. power-of-two) or 25%
    // fragmentation.
    static constexpr float kDefaultMemoryFragmentationLimit = 0.125f;  // 1/8th or 12.5%

    // Amount of memory, expressed as a perecentage memory size, that can
    // increased per allocation. For example, a 2.0 factor means the memory size can double.
    static constexpr float kDefaultMemoryGrowthFactor = 1.25f;  // 25% growth

    class BlockAllocator;

    // MemoryAllocatorBase services a fixed or variable sized MemoryAllocationRequest.
    //
    // Internally, MemoryAllocatorBase sub-allocates existing memory objects into smaller chucks
    // (called memory blocks) or allocates whole memory objects then decides which memory blocks
    // or objects to cache. Since cached memory objects count against the application's memory
    // usage, freeing this cache periodically by calling ReleaseMemory() is highly recommended.

    // MemoryAllocatorBase can also be created with another MemoryAllocatorBase. MemoryAllocatorBase
    // represents a chain where allocations made between the first-order MemoryAllocatorBase (or
    // parent) and the next MemoryAllocatorBase (or child) form a one-way edge. This allows the
    // first-order MemoryAllocatorBase to sub-allocate from larger blocks provided by the
    // second-order MemoryAllocatorBase and so on.
    class MemoryAllocatorBase : public ObjectBase,
                                public LinkNode<MemoryAllocatorBase>,
                                public RefCounted {
      public:
        // Constructs a standalone MemoryAllocatorBase.
        MemoryAllocatorBase();

        // Constructs a MemoryAllocatorBase that also owns a (child) allocator.
        explicit MemoryAllocatorBase(ScopedRef<MemoryAllocatorBase> next);

        virtual ~MemoryAllocatorBase() override;

        // Attempts creation of a memory allocation.
        //
        // The returned MemoryAllocationBase is only valid for the lifetime of |this|
        // MemoryAllocatorBase.
        virtual ResultOrError<std::unique_ptr<MemoryAllocationBase>> TryAllocateMemory(
            const MemoryAllocationRequest& request);

        // Same as TryAllocateMemory above but leaves the result unwrapped for testing the result
        // directly.
        std::unique_ptr<MemoryAllocationBase> TryAllocateMemoryForTesting(
            const MemoryAllocationRequest& request);

        // Non-blocking version of TryAllocateMemory.
        //
        // Caller must wait for the event to complete before using the resulting allocation.
        std::shared_ptr<MemoryAllocationEvent> TryAllocateMemoryAsync(
            const MemoryAllocationRequest& request);

        // Free a memory allocation.
        //
        // After DeallocateMemory is called, the MemoryAllocationBase is longer valid.
        virtual void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) = 0;

        // Return free memory back to the OS.
        //
        // Returns the amount of memory, in bytes, released. The released size might be smaller then
        // |bytesToRelease| if there was not enough memory or larger if releasable memory doesn't
        // exactly total up to the amount.  A value of UINT64_MAX releases ALL memory held by the
        // allocator.
        virtual uint64_t ReleaseMemory(uint64_t bytesToRelease);

        // Get the fixed-memory sized of the MemoryAllocatorBase.
        //
        // If this allocator only allocates memory blocks using the same size, this value
        // is guarenteed to valid. Otherwise, kInvalidSize is returned to denote any memory size
        // could be created by |this| allocator.
        virtual uint64_t GetMemorySize() const;

        // Get the fixed-memory alignment of the MemoryAllocatorBase.
        // If this allocator only allocates memory using the same alignment, this value
        // is guarenteed to valid. Otherwise, kInvalidOffset is returned to denote any alignment is
        // allowed.
        virtual uint64_t GetMemoryAlignment() const;

        // Get memory allocator usage.
        //
        // Should be overridden when a child or block allocator is used to avoid
        // over-counting.
        virtual MemoryAllocatorStats GetStats() const;

        // Checks if the request is valid.
        MaybeError ValidateRequest(const MemoryAllocationRequest& request) const;

        // Return the next MemoryAllocatorBase.
        MemoryAllocatorBase* GetNextInChain() const;

        // Return the previous MemoryAllocatorBase.
        MemoryAllocatorBase* GetParent() const;

        DEFINE_OBJECT_BASE_OVERRIDES(MemoryAllocatorBase)

      protected:
        // Combine TryAllocateBlock and TryAllocateMemory into a single call so a partial
        // or uninitalized memory allocation cannot be created. If memory cannot be allocated for
        // the block, the block will be deallocated instead of allowing it to leak.
        template <typename GetOrCreateMemoryFn>
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> TrySubAllocateMemory(
            BlockAllocator* allocator,
            uint64_t requestSize,
            uint64_t alignment,
            bool neverAllocate,
            GetOrCreateMemoryFn&& GetOrCreateMemory) {
            MemoryBlock* block = allocator->TryAllocateBlock(requestSize, alignment);
            if (block == nullptr) {
                return {};
            }

            ResultOrError<std::unique_ptr<MemoryAllocationBase>> result = GetOrCreateMemory(block);
            if (!result.IsSuccess()) {
                // NeverAllocate always fails, so suppress it.
                if (!neverAllocate) {
                    ErrorLog(ErrorCode::kAllocationFailed, this)
                        << "Failed to sub-allocate memory range = ["
                        << std::to_string(block->Offset) << ", "
                        << std::to_string(block->Offset + block->Size) << ").";
                }
                allocator->DeallocateBlock(block);
                return result.GetErrorCode();
            }

            std::unique_ptr<MemoryAllocationBase> memoryAllocation = result.AcquireResult();
            ASSERT(memoryAllocation->GetMemory() != nullptr);

            memoryAllocation->GetMemory()->Ref();

            // Caller is be responsible in fully initializing the memory allocation.
            // This is because TrySubAllocateMemory() does not necessarily know how to map the
            // final sub-allocated block to created memory.
            return std::make_unique<MemoryAllocationBase>(
                nullptr, memoryAllocation->GetMemory(), kInvalidOffset,
                AllocationMethod::kUndefined, block, requestSize);
        }

        void InsertIntoChain(ScopedRef<MemoryAllocatorBase> next);

        MemoryAllocatorStats mStats = {};

        mutable std::mutex mMutex;

      private:
        ScopedRef<MemoryAllocatorBase> mNext;
        MemoryAllocatorBase* mParent = nullptr;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_MEMORYALLOCATOR_H_
