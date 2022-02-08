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

#include "gpgmm/JSONSerializer.h"
#include "gpgmm/Memory.h"
#include "gpgmm/common/Assert.h"
#include "gpgmm/common/Math.h"

namespace gpgmm {

    // SlabMemoryAllocator

    SlabMemoryAllocator::SlabMemoryAllocator(uint64_t blockSize,
                                             uint64_t maxSlabSize,
                                             uint64_t slabSize,
                                             uint64_t slabAlignment,
                                             double slabFragmentationLimit,
                                             MemoryAllocator* memoryAllocator)
        : mBlockSize(blockSize),
          mMaxSlabSize(maxSlabSize),
          mSlabSize(slabSize),
          mSlabAlignment(slabAlignment),
          mSlabFragmentationLimit(slabFragmentationLimit),
          mMemoryAllocator(memoryAllocator) {
        ASSERT(IsPowerOfTwo(mMaxSlabSize));
        ASSERT(mMemoryAllocator != nullptr);
        ASSERT(mSlabSize <= mMaxSlabSize);
    }

    SlabMemoryAllocator::~SlabMemoryAllocator() {
        for (SlabCache& cache : mCaches) {
            cache.FreeList.DeleteAll();
            cache.FullList.DeleteAll();
        }
    }

    uint64_t SlabMemoryAllocator::ComputeSlabSize(uint64_t allocationSize) const {
        // If the left over empty space is less than |mSlabFragmentationLimit| x slab size,
        // then the fragmentation is acceptable and we are done. For example, a 4MB slab and and a
        // 512KB block fits exactly 8 blocks with no wasted space. But a 3MB block has 1MB worth of
        // empty space leftover which exceeds |mSlabFragmentationLimit| x slab size or 500KB.
        ASSERT(allocationSize <= mBlockSize);

        // Slabs are grown in multiple of powers of two of the block size or |mSlabSize|
        // if specified.
        uint64_t slabSize = std::max(mSlabSize, mBlockSize);
        const uint64_t wastedBytes = mBlockSize - allocationSize;
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
                                                                             bool neverAllocate) {
        TRACE_EVENT_CALL_SCOPED("SlabMemoryAllocator.TryAllocateMemory");
        if (size > mBlockSize) {
            LogMessageEvent(LogSeverity::Info, "SlabMemoryAllocator.TryAllocateMemory",
                            "Allocation size exceeded the block size.  (" + std::to_string(size) +
                                " vs " + std::to_string(mBlockSize) + " bytes).",
                            ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED);
            return {};
        }

        const uint64_t slabSize = ComputeSlabSize(size);
        if (slabSize > mMaxSlabSize) {
            LogMessageEvent(LogSeverity::Info, "SlabMemoryAllocator.TryAllocateMemory",
                            "Slab size exceeded the max slab size. (" + std::to_string(slabSize) +
                                " vs " + std::to_string(mMaxSlabSize) + " bytes).",
                            ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED);
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
        GPGMM_TRY_ASSIGN(TrySubAllocateMemory(
                             &slab->Allocator, mBlockSize, alignment,
                             [&](const auto& block) -> MemoryBase* {
                                 if (slab->SlabMemory == nullptr) {
                                     GPGMM_TRY_ASSIGN(mMemoryAllocator->TryAllocateMemory(
                                                          slabSize, mSlabAlignment, neverAllocate),
                                                      slab->SlabMemory);
                                 }
                                 return slab->SlabMemory->GetMemory();
                             }),
                         subAllocation);

        // Slab must be referenced seperately from its memory because slab memory could be already
        // allocated from another allocator. Only once the final allocation on the slab is
        // deallocated, can slab memory be safely released.
        slab->Ref();

        // Wrap the block in the containing slab. Since the slab's block could reside in another
        // allocated block, the slab's allocation offset must be made relative to slab's underlying
        // memory and not the slab.
        SlabControlBlock* blockInSlab = new SlabControlBlock{subAllocation->GetBlock(), slab};
        blockInSlab->Size = subAllocation->GetBlock()->Size;
        blockInSlab->Offset = slab->SlabMemory->GetOffset() + subAllocation->GetBlock()->Offset;

        mStats.UsedBlockCount++;
        mStats.UsedBlockUsage += blockInSlab->Size;

        return std::make_unique<MemoryAllocation>(this, subAllocation->GetMemory(),
                                                  blockInSlab->Offset,
                                                  AllocationMethod::kSubAllocated, blockInSlab);
    }

    void SlabMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        TRACE_EVENT_CALL_SCOPED("SlabMemoryAllocator.DeallocateMemory");

        const SlabControlBlock* blockInSlab =
            static_cast<SlabControlBlock*>(allocation->GetBlock());
        ASSERT(blockInSlab != nullptr);

        Slab* slab = blockInSlab->pSlab;
        ASSERT(slab != nullptr);

        MemoryBase* slabMemory = allocation->GetMemory();
        ASSERT(slabMemory != nullptr);

        // Splice the slab from the full-list to free-list.
        if (slab->IsFull()) {
            SlabCache* cache = GetOrCreateCache(slabMemory->GetSize());
            slab->RemoveFromList();
            slab->InsertBefore(cache->FreeList.head());
        }

        mStats.UsedBlockCount--;
        mStats.UsedBlockUsage -= blockInSlab->Size;

        Block* block = blockInSlab->pBlock;
        slab->Allocator.DeallocateBlock(block);
        delete blockInSlab;

        slabMemory->Unref();

        // If the slab will be empty, release the underlying memory.
        if (slab->Unref()) {
            mMemoryAllocator->DeallocateMemory(slab->SlabMemory.release());
        }
    }

    MEMORY_ALLOCATOR_INFO SlabMemoryAllocator::QueryInfo() const {
        MEMORY_ALLOCATOR_INFO info = {};
        info.UsedBlockUsage += mStats.UsedBlockUsage;
        info.UsedBlockCount += mStats.UsedBlockCount;
        return info;
    }

    uint64_t SlabMemoryAllocator::GetPoolSizeForTesting() const {
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
                                           std::unique_ptr<MemoryAllocator> memoryAllocator)
        : mMinBlockSize(minBlockSize),
          mMaxSlabSize(maxSlabSize),
          mSlabSize(slabSize),
          mSlabAlignment(slabAlignment),
          mSlabFragmentationLimit(slabFragmentationLimit),
          mMemoryAllocator(std::move(memoryAllocator)) {
        ASSERT(IsPowerOfTwo(mMaxSlabSize));
    }

    SlabCacheAllocator::~SlabCacheAllocator() {
        ASSERT(mSizeCache.GetSize() == 0);
    }

    std::unique_ptr<MemoryAllocation> SlabCacheAllocator::TryAllocateMemory(uint64_t size,
                                                                            uint64_t alignment,
                                                                            bool neverAllocate) {
        TRACE_EVENT_CALL_SCOPED("SlabCacheAllocator.TryAllocateMemory");

        const uint64_t blockSize = AlignTo(size, mMinBlockSize);

        // Attempting to allocate a block larger then the slab will always fail.
        if (mSlabSize != 0 && blockSize > mSlabSize) {
            LogMessageEvent(LogSeverity::Info, "SlabMemoryAllocator.TryAllocateMemory",
                            "Aligned allocation size exceeded the slab size (" +
                                std::to_string(blockSize) + " vs " + std::to_string(mSlabSize) +
                                " bytes).",
                            ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED);
            return {};
        }

        // Create a slab allocator for the new entry.
        auto entry = mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(blockSize));

        // Create a slab allocator for the new entry.
        SlabMemoryAllocator* slabAllocator = entry->GetValue().SlabAllocator;
        if (slabAllocator == nullptr) {
            slabAllocator = static_cast<SlabMemoryAllocator*>(
                SlabCacheAllocator::AppendChild(std::make_unique<SlabMemoryAllocator>(
                    blockSize, mMaxSlabSize, mSlabSize, mSlabAlignment, mSlabFragmentationLimit,
                    mMemoryAllocator.get())));
            entry->GetValue().SlabAllocator = slabAllocator;
        }

        ASSERT(slabAllocator != nullptr);

        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(slabAllocator->TryAllocateMemory(size, alignment, neverAllocate),
                         subAllocation);

        // Hold onto the cached allocator until the last allocation gets deallocated.
        entry->Ref();

        return std::make_unique<MemoryAllocation>(
            this, subAllocation->GetMemory(), subAllocation->GetOffset(),
            AllocationMethod::kSubAllocated, subAllocation->GetBlock());
    }

    void SlabCacheAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        TRACE_EVENT_CALL_SCOPED("SlabCacheAllocator.DeallocateMemory");

        auto entry = mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(allocation->GetSize()));

        SlabMemoryAllocator* slabAllocator = entry->GetValue().SlabAllocator;
        ASSERT(slabAllocator != nullptr);

        slabAllocator->DeallocateMemory(allocation);

        // Remove the cached allocator if this is the last allocation. Once |entry| goes out of
        // scope, it will unlink itself from the cache.
        entry->Unref();
        if (entry->HasOneRef()) {
            SlabCacheAllocator::RemoveChild(slabAllocator);
        }
    }

    MEMORY_ALLOCATOR_INFO SlabCacheAllocator::QueryInfo() const {
        MEMORY_ALLOCATOR_INFO info = {};
        // Underlying memory allocator is weakly shared between cached slab allocators so it
        // should only be counted once (by the SlabCacheAllocator).
        for (const auto& entry : mSizeCache) {
            const MEMORY_ALLOCATOR_INFO& childInfo = entry->GetValue().SlabAllocator->QueryInfo();
            info.UsedBlockCount += childInfo.UsedBlockCount;
            info.UsedBlockUsage += childInfo.UsedBlockUsage;
        }

        const MEMORY_ALLOCATOR_INFO& memoryInfo = mMemoryAllocator->QueryInfo();
        info.UsedMemoryUsage += memoryInfo.UsedMemoryUsage;
        info.UsedMemoryCount += memoryInfo.UsedMemoryCount;

        return info;
    }

    uint64_t SlabCacheAllocator::GetPoolSizeForTesting() const {
        uint64_t count = 0;
        for (const auto& entry : mSizeCache) {
            const SlabMemoryAllocator* allocator = entry->GetValue().SlabAllocator;
            ASSERT(allocator != nullptr);
            count += allocator->GetPoolSizeForTesting();
        }
        return count;
    }

}  // namespace gpgmm
