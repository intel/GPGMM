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
                                                                             bool cacheSize) {
        TRACE_EVENT_CALL_SCOPED("SlabMemoryAllocator.TryAllocateMemory");
        if (size > mBlockSize) {
            RecordMessage(LogSeverity::Debug, "SlabMemoryAllocator.TryAllocateMemory",
                          "Allocation size exceeded the block size (" + std::to_string(size) +
                              " vs " + std::to_string(mBlockSize) + " bytes).",
                          ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED);
            return {};
        }

        const uint64_t slabSize = ComputeSlabSize(size);
        if (slabSize > mMaxSlabSize) {
            RecordMessage(LogSeverity::Debug, "SlabMemoryAllocator.TryAllocateMemory",
                          "Slab size exceeded the max slab size (" + std::to_string(slabSize) +
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
        GPGMM_TRY_ASSIGN(TrySubAllocateMemory(&slab->Allocator, mBlockSize, alignment,
                                              [&](const auto& block) -> MemoryBase* {
                                                  if (slab->SlabMemory == nullptr) {
                                                      GPGMM_TRY_ASSIGN(
                                                          mMemoryAllocator->TryAllocateMemory(
                                                              slabSize, mSlabAlignment,
                                                              neverAllocate, cacheSize),
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

    void SlabMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT_CALL_SCOPED("SlabMemoryAllocator.DeallocateMemory");

        const BlockInSlab* blockInSlab = static_cast<BlockInSlab*>(allocation->GetBlock());
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

        mInfo.UsedBlockCount--;
        mInfo.UsedBlockUsage -= blockInSlab->Size;

        Block* block = blockInSlab->pBlock;
        slab->Allocator.DeallocateBlock(block);
        SafeDelete(blockInSlab);

        slabMemory->Unref();

        // If the slab will be empty, release the underlying memory.
        if (slab->Unref()) {
            mMemoryAllocator->DeallocateMemory(std::move(slab->SlabMemory));
        }
    }

    MEMORY_ALLOCATOR_INFO SlabMemoryAllocator::QueryInfo() const {
        MEMORY_ALLOCATOR_INFO info = mInfo;
        const MEMORY_ALLOCATOR_INFO& memoryInfo = mMemoryAllocator->QueryInfo();
        info.UsedMemoryCount = memoryInfo.UsedMemoryCount;
        info.UsedMemoryUsage = memoryInfo.UsedMemoryUsage;
        info.FreeMemoryUsage = memoryInfo.FreeMemoryUsage;
        return info;
    }

    uint64_t SlabMemoryAllocator::GetSlabSizeForTesting() const {
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
        : MemoryAllocator(std::move(memoryAllocator)),
          mMinBlockSize(minBlockSize),
          mMaxSlabSize(maxSlabSize),
          mSlabSize(slabSize),
          mSlabAlignment(slabAlignment),
          mSlabFragmentationLimit(slabFragmentationLimit) {
        ASSERT(IsPowerOfTwo(mMaxSlabSize));
    }

    SlabCacheAllocator::~SlabCacheAllocator() {
        mSizeCache.RemoveAndDeleteAll();
        mSlabAllocators.RemoveAndDeleteAll();
    }

    std::unique_ptr<MemoryAllocation> SlabCacheAllocator::TryAllocateMemory(uint64_t size,
                                                                            uint64_t alignment,
                                                                            bool neverAllocate,
                                                                            bool cacheSize) {
        TRACE_EVENT_CALL_SCOPED("SlabCacheAllocator.TryAllocateMemory");
        GPGMM_CHECK_NONZERO(size);

        const uint64_t blockSize = AlignTo(size, mMinBlockSize);

        // Create a slab allocator for the new entry.
        auto entry = mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(blockSize), cacheSize);

        // Create a slab allocator for the new entry.
        SlabMemoryAllocator* slabAllocator = entry->GetValue().pSlabAllocator;
        if (slabAllocator == nullptr) {
            slabAllocator =
                new SlabMemoryAllocator(blockSize, mMaxSlabSize, mSlabSize, mSlabAlignment,
                                        mSlabFragmentationLimit, GetFirstChild());
            entry->GetValue().pSlabAllocator = slabAllocator;
            mSlabAllocators.Append(slabAllocator);
        }

        ASSERT(slabAllocator != nullptr);

        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(
            slabAllocator->TryAllocateMemory(blockSize, alignment, neverAllocate, cacheSize),
            subAllocation);

        // Hold onto the cached allocator until the last allocation gets deallocated.
        entry->Ref();

        return std::make_unique<MemoryAllocation>(
            this, subAllocation->GetMemory(), subAllocation->GetOffset(),
            subAllocation->GetMethod(), subAllocation->GetBlock());
    }

    void SlabCacheAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT_CALL_SCOPED("SlabCacheAllocator.DeallocateMemory");

        auto entry = mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(allocation->GetSize()), false);

        SlabMemoryAllocator* slabAllocator = entry->GetValue().pSlabAllocator;
        ASSERT(slabAllocator != nullptr);

        slabAllocator->DeallocateMemory(std::move(allocation));

        // Remove the cached allocator if this is the last allocation. Once |entry| goes out of
        // scope, it will unlink itself from the cache.
        entry->Unref();
        if (entry->HasOneRef()) {
            SafeDelete(slabAllocator);
        }
    }

    MEMORY_ALLOCATOR_INFO SlabCacheAllocator::QueryInfo() const {
        MEMORY_ALLOCATOR_INFO info = {};
        for (const auto& entry : mSizeCache) {
            const MEMORY_ALLOCATOR_INFO& childInfo = entry->GetValue().pSlabAllocator->QueryInfo();
            info.UsedBlockCount += childInfo.UsedBlockCount;
            info.UsedBlockUsage += childInfo.UsedBlockUsage;
        }
        // Memory allocator is common across slab allocators.
        const MEMORY_ALLOCATOR_INFO& memoryInfo = GetFirstChild()->QueryInfo();
        info.FreeMemoryUsage = memoryInfo.FreeMemoryUsage;
        info.UsedMemoryCount = memoryInfo.UsedMemoryCount;
        info.UsedMemoryUsage = memoryInfo.UsedMemoryUsage;
        return info;
    }

    uint64_t SlabCacheAllocator::GetSlabCacheSizeForTesting() const {
        uint64_t count = 0;
        for (const auto& entry : mSizeCache) {
            const SlabMemoryAllocator* allocator = entry->GetValue().pSlabAllocator;
            ASSERT(allocator != nullptr);
            count += allocator->GetSlabSizeForTesting();
        }
        return count;
    }

}  // namespace gpgmm
