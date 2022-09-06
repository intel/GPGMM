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

    /** \struct MemoryAllocatorInfo
    Information about the memory allocator.
    */
    struct MemoryAllocatorInfo {
        /** \brief Number of used sub-allocated blocks within the same memory.
         */
        uint32_t UsedBlockCount;

        /** \brief Total size, in bytes, of used sub-allocated blocks.
         */
        uint64_t UsedBlockUsage;

        /** \brief Number of used memory allocations.
         */
        uint32_t UsedMemoryCount;

        /** \brief Total size, in bytes, of used memory.
         */
        uint64_t UsedMemoryUsage;

        /** \brief Total size, in bytes, of free memory.
         */
        uint64_t FreeMemoryUsage;

        /** \brief Cache misses not eliminated by prefetching.
         */
        uint64_t PrefetchedMemoryMisses;

        /** \brief Cache misses eliminated because of prefetching.
         */
        uint64_t PrefetchedMemoryMissesEliminated;

        /** \brief Requested size was NOT cached.
         */
        uint64_t SizeCacheMisses;

        /** \brief Requested size was cached.
         */
        uint64_t SizeCacheHits;

        MemoryAllocatorInfo& operator+=(const MemoryAllocatorInfo& rhs) {
            UsedBlockCount += rhs.UsedBlockCount;
            UsedBlockUsage += rhs.UsedBlockUsage;
            FreeMemoryUsage += rhs.FreeMemoryUsage;
            UsedMemoryUsage += rhs.UsedMemoryUsage;
            UsedMemoryCount += rhs.UsedMemoryCount;

            PrefetchedMemoryMisses += rhs.PrefetchedMemoryMisses;
            PrefetchedMemoryMissesEliminated += rhs.PrefetchedMemoryMissesEliminated;

            SizeCacheMisses += rhs.SizeCacheMisses;
            SizeCacheHits += rhs.SizeCacheHits;

            return *this;
        }
    };

    class AllocateMemoryTask;

    /** \brief MemoryAllocationEvent

    Event used to notify caller when AllocateMemoryTask has completed.
    */
    class MemoryAllocationEvent final : public Event {
      public:
        /** \brief Construct a MemoryAllocationEvent.

        @param event Pointer to Event, which gets signaled when memory gets allocated.
        @param task Pointer to Task, which runs allocate memory.
        */
        MemoryAllocationEvent(std::shared_ptr<Event> event,
                              std::shared_ptr<AllocateMemoryTask> task);

        // Event overrides
        void Wait() override;

        /** \brief Acquire the memory allocation.

        \return Pointer to MemoryAllocation that was allocated.
        */
        std::unique_ptr<MemoryAllocation> AcquireAllocation() const;

      private:
        void Signal() override;
        bool IsSignaled() override;

        std::shared_ptr<AllocateMemoryTask> mTask;
        std::shared_ptr<Event> mEvent;
    };

    /** \struct MemoryAllocationRequest
    Describes a request to allocate memory.
    */
    struct MemoryAllocationRequest {
        /** \brief Request the size, in bytes, of the allocation.

        The requested allocation size is the minimum size required to allocate.
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

    /** \brief MemoryAllocator services a fixed or variable sized MemoryAllocationRequest.

    Internally, MemoryAllocator sub-allocates existing memory objects into smaller chucks
    (called memory blocks) or allocates whole memory objects then decides which memory blocks
    or objects to cache. Since cached memory objects count against the application's memory
    usage, freeing this cache periodically by calling ReleaseMemory() is highly recommended.
    */
    class MemoryAllocator : public AllocatorBase, public AllocatorNode<MemoryAllocator> {
      public:
        /** \brief Constructs a standalone MemoryAllocator.

        A "standalone MemoryAllocator" means it does not depend on any other allocator to service
        requests.
        */
        MemoryAllocator();

        /** \brief Constructs a MemoryAllocator that also owns a (child) allocator.

        @param next A dependant MemoryAllocator that will be used for requesting more memory.
        */
        explicit MemoryAllocator(std::unique_ptr<MemoryAllocator> next);

        virtual ~MemoryAllocator() override;

        /** \brief Create a memory allocation.

        Creates a MemoryAllocation that has at-least requested size whose value is a multiple of the
        requested alignment. If it cannot, return nullptr. The returned allocation is only valid for
        the lifetime of MemoryAllocator.

        @param request A MemoryAllocationRequest to describes what to allocate.

        \return A pointer to MemoryAllocation. If NULL, the request could not be full-filled.
        */
        virtual std::unique_ptr<MemoryAllocation> TryAllocateMemory(
            const MemoryAllocationRequest& request);

        /** \brief Non-blocking version of TryAllocateMemory.

        Caller must wait for the event to complete before using the resulting allocation.

        \return A pointer to MemoryAllocationEvent. Must be non-null.
        */
        std::shared_ptr<MemoryAllocationEvent> TryAllocateMemoryAsync(
            const MemoryAllocationRequest& request);

        /** \brief Free a memory allocation.

        After DeallocateMemory is called, the MemoryAllocation is longer valid.

        @param allocation A MemoryAllocation to de-allocate. Must be non-null.
        */
        virtual void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) = 0;

        /** \brief Return free memory back to the OS.

        @param bytesToRelease Amount of memory to release, in bytes. A value of UINT64_MAX
        releases ALL memory held by the allocator.

        \return Amount of memory, in bytes, released. The released size might be smaller then
        bytesToRelease if there was not enough memory or larger if releasable memory doesn't exactly
        total up to the amount.
        */
        virtual uint64_t ReleaseMemory(uint64_t bytesToRelease);

        /** \brief Get the fixed-memory sized of the MemoryAllocator.

        If this allocator only allocates memory blocks using the same size, this value
        is guarenteed to valid. Otherwise, kInvalidSize is returned to denote any memory size
        could be created by |this| allocator.

        \return Size of memory, in bytes.
        */
        virtual uint64_t GetMemorySize() const;

        /** \brief Get the fixed-memory alignment of the MemoryAllocator.

        If this allocator only allocates memory using the same alignment, this value
        is guarenteed to valid. Otherwise, kInvalidOffset is returned to denote any alignment is
        allowed.

        \return Alignment of memory, in bytes.
        */
        virtual uint64_t GetMemoryAlignment() const;

        /** \brief Get memory allocator usage.

        Should be overridden when a child or block allocator is used to avoid
        over-counting.

        \return A MemoryAllocatorInfo struct containing the current usage.
        */
        virtual MemoryAllocatorInfo GetInfo() const;

        /** \brief Identifies the allocator type.

        The type is used for profiling and debugging purposes only.
        */
        const char* GetTypename() const override;

        /** \brief Checks if the request is valid.

        @param request A MemoryAllocationRequest to check.

        \return True if the request is valid. If non-valid, it cannot be allocated.
        */
        bool ValidateRequest(const MemoryAllocationRequest& request) const;

      protected:
        // Combine TryAllocateBlock and TryAllocateMemory into a single call so a partial
        // or uninitalized memory allocation cannot be created. If memory cannot be allocated for
        // the block, the block will be deallocated instead of allowing it to leak.
        template <typename GetOrCreateMemoryFn>
        static std::unique_ptr<MemoryAllocation> TrySubAllocateMemory(
            BlockAllocator* allocator,
            uint64_t requestSize,
            uint64_t alignment,
            bool neverAllocate,
            GetOrCreateMemoryFn&& GetOrCreateMemory) {
            MemoryBlock* block = nullptr;
            GPGMM_TRY_ASSIGN(allocator->TryAllocateBlock(requestSize, alignment), block);

            MemoryBase* memory = GetOrCreateMemory(block);
            if (memory == nullptr) {
                // NeverAllocate always fails, so suppress it.
                if (!neverAllocate) {
                    DebugLog() << std::string(allocator->GetTypename()) +
                                      " failed to sub-allocate memory range = ["
                               << std::to_string(block->Offset) << ", "
                               << std::to_string(block->Offset + block->Size) << ").";
                }
                allocator->DeallocateBlock(block);
                return nullptr;
            }

            ASSERT(memory != nullptr);
            memory->AddSubAllocationRef();

            // Caller is be responsible in fully initializing the memory allocation.
            // This is because TrySubAllocateMemory() does not necessarily know how to map the
            // final sub-allocated block to created memory.
            return std::make_unique<MemoryAllocation>(
                nullptr, memory, kInvalidOffset, AllocationMethod::kUndefined, block, requestSize);
        }

        MemoryAllocatorInfo mInfo = {};

        mutable std::mutex mMutex;
        std::shared_ptr<ThreadPool> mThreadPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORYALLOCATOR_H_
