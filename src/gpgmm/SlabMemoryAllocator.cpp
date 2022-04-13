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

#include "gpgmm/SlabMemoryAllocator.h"

#include "gpgmm/Debug.h"
#include "gpgmm/Memory.h"
#include "gpgmm/common/Assert.h"
#include "gpgmm/common/Math.h"
#include "gpgmm/common/Utils.h"

#include <algorithm>  // std::max

namespace gpgmm {

    constexpr static uint64_t kSlabPrefetchTotalBlockCount = 4u;
    constexpr static double kSlabPrefetchUsageThreshold = 0.50;

    // SlabMemoryAllocator

    SlabMemoryAllocator::SlabMemoryAllocator(uint64_t blockSize,
                                             uint64_t maxSlabSize,
                                             uint64_t slabSize,
                                             uint64_t slabAlignment,
                                             double slabFragmentationLimit,
                                             bool prefetchSlab,
                                             MemoryAllocator* memoryAllocator)
        : mBlockSize(blockSize),
          mMaxSlabSize(maxSlabSize),
          mSlabSize(slabSize),
          mSlabAlignment(slabAlignment),
          mSlabFragmentationLimit(slabFragmentationLimit),
          mPrefetchSlab(prefetchSlab),
          mMemoryAllocator(memoryAllocator) {
        ASSERT(IsPowerOfTwo(mMaxSlabSize));
        ASSERT(mMemoryAllocator != nullptr);
        ASSERT(mSlabSize <= mMaxSlabSize);
    }

    SlabMemoryAllocator::~SlabMemoryAllocator() {
        if (mNextSlabAllocationEvent != nullptr) {
            mNextSlabAllocationEvent->Wait();
            mMemoryAllocator->DeallocateMemory(mNextSlabAllocationEvent->AcquireAllocation());
        }

        for (SlabCache& cache : mCaches) {
            cache.FreeList.RemoveAndDeleteAll();
            cache.FullList.RemoveAndDeleteAll();
        }
    }

    uint64_t SlabMemoryAllocator::ComputeSlabSize(uint64_t size) const {
        // If the left over empty space is less than |mSlabFragmentationLimit| x slab size,
        // then the fragmentation is acceptable and we are done. For example, a 4MB slab and and a
        // 512KB block fits exactly 8 blocks with no wasted space. But a 3MB block has 1MB worth of
        // empty space leftover which exceeds |mSlabFragmentationLimit| x slab size or 500KB.
        ASSERT(size <= mBlockSize);

        // Slabs are grown in multiple of powers of two of the block size or |mSlabSize|
        // if specified.
        uint64_t slabSize = std::max(mSlabSize, mBlockSize);
        const uint64_t wastedBytes = mBlockSize - size;
        while (wastedBytes > (mSlabFragmentationLimit * slabSize)) {
            slabSize *= 2;
        }

        return NextPowerOfTwo(slabSize);
    }

    SlabMemoryAllocator::SlabCache* SlabMemoryAllocator::GetOrCreateCache(uint64_t slabSize) {
        const uint64_t cacheIndex = Log2(mMaxSlabSize) - Log2(slabSize);
        if (cacheIndex >= mCaches.size()) {
            mCaches.resize(cacheIndex + 1);
        }
        SlabCache* cache = &mCaches[cacheIndex];
        ASSERT(cache != nullptr);
        return cache;
    }

    std::unique_ptr<MemoryAllocation> SlabMemoryAllocator::TryAllocateMemory(uint64_t size,
                                                                             uint64_t alignment,
                                                                             bool neverAllocate,
                                                                             bool cacheSize,
                                                                             bool prefetchMemory) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        if (size > mBlockSize) {
            DebugEvent("SlabMemoryAllocator.TryAllocateMemory", ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED)
                << "Allocation size exceeded the block size (" + std::to_string(size) + " vs " +
                       std::to_string(mBlockSize) + " bytes).";
            return {};
        }

        const uint64_t slabSize = ComputeSlabSize(size);
        if (slabSize > mMaxSlabSize) {
            DebugEvent("SlabMemoryAllocator.TryAllocateMemory", ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED)
                << "Slab size exceeded the max slab size (" + std::to_string(slabSize) + " vs " +
                       std::to_string(mMaxSlabSize) + " bytes).";
            return {};
        }

        // Get or create the cache containing slabs of the slab size.
        SlabCache* cache = GetOrCreateCache(slabSize);
        ASSERT(cache != nullptr);

        auto* node = cache->FreeList.head();

        Slab* slab = nullptr;
        if (!cache->FreeList.empty()) {
            slab = node->value();
        }

        // Splice the full slab from the free-list to full-list.
        if (slab != nullptr && slab->IsFull()) {
            node->RemoveFromList();
            node->InsertBefore(cache->FullList.head());
        }

        // Push new slab at HEAD if free-list is empty.
        if (cache->FreeList.empty()) {
            Slab* newSlab = new Slab(slabSize / mBlockSize, mBlockSize);
            newSlab->InsertBefore(cache->FreeList.head());
            slab = newSlab;
        }

        ASSERT(!cache->FreeList.empty());
        ASSERT(slab != nullptr);

        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(
            TrySubAllocateMemory(
                &slab->Allocator, mBlockSize, alignment,
                [&](const auto& block) -> MemoryBase* {
                    if (slab->SlabMemory == nullptr) {
                        // Resolve the pending pre-fetched allocation.
                        if (mNextSlabAllocationEvent != nullptr) {
                            mNextSlabAllocationEvent->Wait();
                            slab->SlabMemory = mNextSlabAllocationEvent->AcquireAllocation();
                            mNextSlabAllocationEvent.reset();
                        } else {
                            GPGMM_TRY_ASSIGN(mMemoryAllocator->TryAllocateMemory(
                                                 slabSize, mSlabAlignment, neverAllocate, cacheSize,
                                                 /*prefetchMemory*/ false),
                                             slab->SlabMemory);
                        }
                    }
                    return slab->SlabMemory->GetMemory();
                }),
            subAllocation);

        // Slab must be referenced seperately from its memory because slab memory could be already
        // allocated from another allocator. Only once the final allocation on the slab is
        // deallocated, can slab memory be safely released.
        slab->Ref();

        // Prefetch memory for future slab.
        //
        // Algorithm is overly conservative since waiting for the device to return prefetched memory
        // could block a current allocation from being created until the device is free.
        //
        // Prefetch occurs when at-least one slab becomes full and the next slab is half used and
        // there are at-least two allocations of capacity left to hide the pre-fetch latency.
        //
        // TODO: Measure if the slab allocation time remaining exceeds the prefetch memory task
        // time before deciding to prefetch.
        //
        if ((prefetchMemory || mPrefetchSlab) && !neverAllocate &&
            mNextSlabAllocationEvent == nullptr && cache->FullList.head() != nullptr &&
            slab->GetUsedPercent() >= kSlabPrefetchUsageThreshold &&
            slab->BlockCount >= kSlabPrefetchTotalBlockCount) {
            mNextSlabAllocationEvent =
                mMemoryAllocator->TryAllocateMemoryAsync(slabSize, mSlabAlignment);
        }

        // Wrap the block in the containing slab. Since the slab's block could reside in another
        // allocated block, the slab's allocation offset must be made relative to slab's underlying
        // memory and not the slab.
        BlockInSlab* blockInSlab = new BlockInSlab();
        blockInSlab->pBlock = subAllocation->GetBlock();
        blockInSlab->pSlab = slab;
        blockInSlab->Size = subAllocation->GetBlock()->Size;
        blockInSlab->Offset = slab->SlabMemory->GetOffset() + subAllocation->GetBlock()->Offset;

        mInfo.UsedBlockCount++;
        mInfo.UsedBlockUsage += blockInSlab->Size;

        return std::make_unique<MemoryAllocation>(this, subAllocation->GetMemory(),
                                                  blockInSlab->Offset,
                                                  AllocationMethod::kSubAllocated, blockInSlab);
    }

    void SlabMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> subAllocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        const BlockInSlab* blockInSlab = static_cast<BlockInSlab*>(subAllocation->GetBlock());
        ASSERT(blockInSlab != nullptr);

        Slab* slab = blockInSlab->pSlab;
        ASSERT(slab != nullptr);

        MemoryBase* slabMemory = subAllocation->GetMemory();
        ASSERT(slabMemory != nullptr);

        // Splice the slab from the full-list to free-list.
        if (slab->IsFull()) {
            SlabCache* cache = GetOrCreateCache(slabMemory->GetSize());
            slab->RemoveFromList();
            slab->InsertBefore(cache->FreeList.head());
        }

        mInfo.UsedBlockCount--;
        mInfo.UsedBlockUsage -= blockInSlab->Size;

        MemoryBlock* block = blockInSlab->pBlock;
        slab->Allocator.DeallocateBlock(block);
        SafeDelete(blockInSlab);

        slabMemory->Unref();

        // If the slab will be empty, release the underlying memory.
        if (slab->Unref()) {
            mMemoryAllocator->DeallocateMemory(std::move(slab->SlabMemory));
        }
    }

    MEMORY_ALLOCATOR_INFO SlabMemoryAllocator::QueryInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        MEMORY_ALLOCATOR_INFO result = mInfo;
        const MEMORY_ALLOCATOR_INFO& info = mMemoryAllocator->QueryInfo();
        result.UsedMemoryCount = info.UsedMemoryCount;
        result.UsedMemoryUsage = info.UsedMemoryUsage;
        result.FreeMemoryUsage = info.FreeMemoryUsage;
        return result;
    }

    uint64_t SlabMemoryAllocator::GetSlabSizeForTesting() const {
        std::lock_guard<std::mutex> lock(mMutex);

        uint64_t slabMemoryCount = 0;
        for (const SlabCache& cache : mCaches) {
            for (auto* node = cache.FreeList.head(); node != cache.FreeList.end();
                 node = node->next()) {
                if (node->value()->SlabMemory != nullptr) {
                    slabMemoryCount++;
                }
            }

            for (auto* node = cache.FullList.head(); node != cache.FullList.end();
                 node = node->next()) {
                if (node->value()->SlabMemory != nullptr) {
                    slabMemoryCount++;
                }
            }
        }
        return slabMemoryCount;
    }

    // SlabCacheAllocator

    SlabCacheAllocator::SlabCacheAllocator(uint64_t minBlockSize,
                                           uint64_t maxSlabSize,
                                           uint64_t slabSize,
                                           uint64_t slabAlignment,
                                           double slabFragmentationLimit,
                                           bool prefetchSlab,
                                           std::unique_ptr<MemoryAllocator> memoryAllocator)
        : MemoryAllocator(std::move(memoryAllocator)),
          mMinBlockSize(minBlockSize),
          mMaxSlabSize(maxSlabSize),
          mSlabSize(slabSize),
          mSlabAlignment(slabAlignment),
          mSlabFragmentationLimit(slabFragmentationLimit),
          mPrefetchSlab(prefetchSlab) {
        ASSERT(IsPowerOfTwo(mMaxSlabSize));
    }

    SlabCacheAllocator::~SlabCacheAllocator() {
        mSizeCache.RemoveAndDeleteAll();
        mSlabAllocators.RemoveAndDeleteAll();
    }

    std::unique_ptr<MemoryAllocation> SlabCacheAllocator::TryAllocateMemory(uint64_t size,
                                                                            uint64_t alignment,
                                                                            bool neverAllocate,
                                                                            bool cacheSize,
                                                                            bool prefetchMemory) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabCacheAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_CHECK_NONZERO(size);

        const uint64_t blockSize = AlignTo(size, mMinBlockSize);

        // Create a slab allocator for the new entry.
        auto entry = mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(blockSize), cacheSize);
        SlabMemoryAllocator* slabAllocator = entry->GetValue().pSlabAllocator;
        if (slabAllocator == nullptr) {
            slabAllocator =
                new SlabMemoryAllocator(blockSize, mMaxSlabSize, mSlabSize, mSlabAlignment,
                                        mSlabFragmentationLimit, mPrefetchSlab, GetFirstChild());
            entry->GetValue().pSlabAllocator = slabAllocator;
            mSlabAllocators.Append(slabAllocator);
        }

        ASSERT(slabAllocator != nullptr);

        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(slabAllocator->TryAllocateMemory(blockSize, alignment, neverAllocate,
                                                          cacheSize, prefetchMemory),
                         subAllocation);

        // Hold onto the cached allocator until the last allocation gets deallocated.
        entry->Ref();

        return std::make_unique<MemoryAllocation>(
            this, subAllocation->GetMemory(), subAllocation->GetOffset(),
            subAllocation->GetMethod(), subAllocation->GetBlock());
    }

    void SlabCacheAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> subAllocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabCacheAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        auto entry =
            mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(subAllocation->GetSize()), false);
        SlabMemoryAllocator* slabAllocator = entry->GetValue().pSlabAllocator;
        ASSERT(slabAllocator != nullptr);

        slabAllocator->DeallocateMemory(std::move(subAllocation));

        // If this is the last sub-allocation, remove the cached allocator.
        // Once |entry| goes out of scope, it will unlink itself from the cache.
        entry->Unref();
        if (entry->HasOneRef()) {
            SafeDelete(slabAllocator);
        }
    }

    MEMORY_ALLOCATOR_INFO SlabCacheAllocator::QueryInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);

        MEMORY_ALLOCATOR_INFO result = {};
        for (const auto& entry : mSizeCache) {
            const MEMORY_ALLOCATOR_INFO& info = entry->GetValue().pSlabAllocator->QueryInfo();
            result.UsedBlockCount += info.UsedBlockCount;
            result.UsedBlockUsage += info.UsedBlockUsage;
        }

        // Memory allocator is common across slab allocators.
        {
            const MEMORY_ALLOCATOR_INFO& info = GetFirstChild()->QueryInfo();
            result.FreeMemoryUsage = info.FreeMemoryUsage;
            result.UsedMemoryCount = info.UsedMemoryCount;
            result.UsedMemoryUsage = info.UsedMemoryUsage;
        }

        return result;
    }

    uint64_t SlabCacheAllocator::GetMemorySize() const {
        return GetFirstChild()->GetMemorySize();
    }

    uint64_t SlabCacheAllocator::GetSlabCacheSizeForTesting() const {
        std::lock_guard<std::mutex> lock(mMutex);

        uint64_t count = 0;
        for (const auto& entry : mSizeCache) {
            const SlabMemoryAllocator* allocator = entry->GetValue().pSlabAllocator;
            ASSERT(allocator != nullptr);
            count += allocator->GetSlabSizeForTesting();
        }
        return count;
    }

}  // namespace gpgmm
