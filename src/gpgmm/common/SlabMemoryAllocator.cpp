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

#include "gpgmm/common/SlabMemoryAllocator.h"

#include "gpgmm/common/Debug.h"
#include "gpgmm/common/Memory.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Utils.h"

#include <algorithm>  // std::max

namespace gpgmm {

    constexpr static uint64_t kSlabPrefetchTotalBlockCount = 4u;
    constexpr static double kSlabPrefetchUsageThreshold = 0.50;

    // SlabMemoryAllocator

    SlabMemoryAllocator::SlabMemoryAllocator(uint64_t blockSize,
                                             uint64_t maxSlabSize,
                                             uint64_t minSlabSize,
                                             uint64_t slabAlignment,
                                             double slabFragmentationLimit,
                                             bool allowSlabPrefetch,
                                             double slabGrowthFactor,
                                             MemoryAllocator* memoryAllocator)
        : mLastUsedSlabSize(0),
          mBlockSize(blockSize),
          mSlabAlignment(slabAlignment),
          mMaxSlabSize(maxSlabSize),
          mMinSlabSize(std::max(minSlabSize, mSlabAlignment)),
          mSlabFragmentationLimit(slabFragmentationLimit),
          mAllowSlabPrefetch(allowSlabPrefetch),
          mSlabGrowthFactor(slabGrowthFactor),
          mMemoryAllocator(memoryAllocator) {
        ASSERT(IsPowerOfTwo(mMaxSlabSize));
        ASSERT(mMemoryAllocator != nullptr);
        ASSERT(mSlabGrowthFactor >= 1);
        ASSERT(mSlabAlignment > 0);
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

    // Returns a new slab size of a power-of-two value.
    uint64_t SlabMemoryAllocator::ComputeSlabSize(uint64_t requestSize, uint64_t slabSize) const {
        ASSERT(requestSize <= mBlockSize);

        // If the left over empty space is less than |mSlabFragmentationLimit| x slab size,
        // then the fragmentation is acceptable and we are done. For example, a 4MB slab and and a
        // 512KB block fits exactly 8 blocks with no wasted space. But a 3MB block has 1MB worth of
        // empty space leftover which exceeds |mSlabFragmentationLimit| x slab size or 500KB.
        const uint64_t fragmentedBytes = mBlockSize - requestSize;
        while (requestSize > slabSize || fragmentedBytes > (mSlabFragmentationLimit * slabSize)) {
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

    std::unique_ptr<MemoryAllocation> SlabMemoryAllocator::TryAllocateMemory(
        const MEMORY_ALLOCATION_REQUEST& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_INVALID_IF(request.SizeInBytes > mBlockSize, ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED,
                         "Allocation size exceeded the block size (" +
                             std::to_string(request.SizeInBytes) + " vs " +
                             std::to_string(mBlockSize) + " bytes).");

        uint64_t slabSize =
            ComputeSlabSize(request.SizeInBytes, std::max(mMinSlabSize, mLastUsedSlabSize));
        GPGMM_INVALID_IF(slabSize > mMaxSlabSize, ALLOCATOR_MESSAGE_ID_SIZE_EXCEEDED,
                         "Slab size exceeded the max slab size (" + std::to_string(slabSize) +
                             " vs " + std::to_string(mMaxSlabSize) + " bytes).");

        // Get or create the cache containing slabs of the slab size.
        SlabCache* cache = GetOrCreateCache(slabSize);
        ASSERT(cache != nullptr);

        // Check free-list since HEAD must always exist (linked-list is self-referential).
        auto* pFreeHead = cache->FreeList.head();
        Slab* pFreeSlab = pFreeHead->value();

        // Splice the full slab from the free-list to the full-list.
        if (!cache->FreeList.empty() && pFreeSlab->IsFull()) {
            pFreeHead->RemoveFromList();
            pFreeHead->InsertBefore(cache->FullList.head());
            pFreeSlab = cache->FreeList.head()->value();
            pFreeHead = nullptr;
        }

        // Push new free slab at free-list HEAD
        if (cache->FreeList.empty() || pFreeSlab->IsFull()) {
            // Get the next free slab.
            if (mLastUsedSlabSize > 0) {
                uint64_t newSlabSize =
                    std::min(ComputeSlabSize(request.SizeInBytes, slabSize * mSlabGrowthFactor),
                             mMaxSlabSize);

                // Revert to using the first computed slab size if growth exceeds
                // available memory. Otherwise, the new larger slab could cause out-of-memory.
                if (request.AvailableForAllocation == 0 ||
                    newSlabSize > request.AvailableForAllocation) {
                    DebugEvent(GetTypename()) << "Available memory exceeded by new slab: "
                                              << std::to_string(request.AvailableForAllocation)
                                              << " vs " << std::to_string(newSlabSize) + " bytes).";

                    newSlabSize = slabSize;
                }

                if (newSlabSize > slabSize) {
                    cache = GetOrCreateCache(newSlabSize);
                    slabSize = newSlabSize;
                }
            }

            Slab* pNewFreeSlab = new Slab(SafeDivison(slabSize, mBlockSize), mBlockSize);
            pNewFreeSlab->InsertBefore(cache->FreeList.head());
            pFreeSlab = pNewFreeSlab;
        }

        ASSERT(pFreeSlab != nullptr);
        ASSERT(!pFreeSlab->IsFull());

        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(
            TrySubAllocateMemory(
                &pFreeSlab->Allocator, mBlockSize, request.Alignment,
                [&](const auto& block) -> MemoryBase* {
                    // Re-use existing memory, if the slab isn't new.
                    if (pFreeSlab->SlabMemory != nullptr) {
                        return pFreeSlab->SlabMemory->GetMemory();
                    }

                    // Use pre-fetched memory if possible, else, throw it away.
                    if (mNextSlabAllocationEvent != nullptr) {
                        // Resolve the pending pre-fetched allocation.
                        mNextSlabAllocationEvent->Wait();
                        auto prefetchedMemory = mNextSlabAllocationEvent->AcquireAllocation();
                        mNextSlabAllocationEvent.reset();

                        // Assign pre-fetched memory to the slab.
                        if (prefetchedMemory->GetSize() == slabSize) {
                            pFreeSlab->SlabMemory = std::move(prefetchedMemory);
                            return pFreeSlab->SlabMemory->GetMemory();
                        }

                        DebugEvent(GetTypename())
                            << "Pre-fetch slab memory is incompatible (" << slabSize << " vs  "
                            << prefetchedMemory->GetSize() << " bytes.";

                        mMemoryAllocator->DeallocateMemory(std::move(prefetchedMemory));
                    }

                    // Create memory of specified slab size.
                    MEMORY_ALLOCATION_REQUEST newSlabRequest = request;
                    newSlabRequest.SizeInBytes = slabSize;
                    newSlabRequest.Alignment = mSlabAlignment;
                    newSlabRequest.AlwaysPrefetch = false;

                    GPGMM_TRY_ASSIGN(mMemoryAllocator->TryAllocateMemory(newSlabRequest),
                                     pFreeSlab->SlabMemory);

                    return pFreeSlab->SlabMemory->GetMemory();
                }),
            subAllocation);

        // Slab must be referenced seperately from the underlying memory because slab memory could
        // be already allocated by another allocator. Only once the final allocation on the slab is
        // deallocated, does the slab memory be released.
        pFreeSlab->Ref();

        // Remember the last allocated slab size so if a subsequent allocation requests a new slab,
        // the next slab size will be larger than the previous slab size.
        mLastUsedSlabSize = slabSize;

        // Prefetch memory for future slab.
        //
        // This check is overly conservative since waiting for the device to retrieve pre-fetched
        // memory could block the next allocation from being created until the device becomes free.
        //
        // TODO: Measure if the slab allocation time remaining exceeds the prefetch memory task
        // time before deciding to prefetch.
        if ((request.AlwaysPrefetch || mAllowSlabPrefetch) && !request.NeverAllocate &&
            mNextSlabAllocationEvent == nullptr &&
            pFreeSlab->GetUsedPercent() >= kSlabPrefetchUsageThreshold &&
            pFreeSlab->GetBlockCount() >= kSlabPrefetchTotalBlockCount) {
            // If a subsequent TryAllocateMemory() uses a request size different than the current
            // request size, memory required for the next slab could be the wrong size. If so,
            // pre-fetching did not pay off and the pre-fetched memory will be de-allocated instead.
            const uint32_t nextSlabSize = std::min(
                ComputeSlabSize(request.SizeInBytes, mLastUsedSlabSize * mSlabGrowthFactor),
                mMaxSlabSize);

            MEMORY_ALLOCATION_REQUEST prefetchSlabRequest = {};
            prefetchSlabRequest.SizeInBytes = nextSlabSize;
            prefetchSlabRequest.Alignment = mSlabAlignment;
            prefetchSlabRequest.NeverAllocate = false;
            prefetchSlabRequest.CacheSize = true;
            prefetchSlabRequest.AlwaysPrefetch = false;

            mNextSlabAllocationEvent =
                mMemoryAllocator->TryAllocateMemoryAsync(prefetchSlabRequest);
        }

        // Wrap the block in the containing slab. Since the slab's block could reside in another
        // allocated block, the slab's allocation offset must be made relative to slab's underlying
        // memory and not the slab.
        BlockInSlab* blockInSlab = new BlockInSlab();
        blockInSlab->pBlock = subAllocation->GetBlock();
        blockInSlab->pSlab = pFreeSlab;
        blockInSlab->Size = subAllocation->GetBlock()->Size;
        blockInSlab->Offset =
            pFreeSlab->SlabMemory->GetOffset() + subAllocation->GetBlock()->Offset;

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

    MEMORY_ALLOCATOR_INFO SlabMemoryAllocator::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        MEMORY_ALLOCATOR_INFO result = mInfo;
        const MEMORY_ALLOCATOR_INFO& info = mMemoryAllocator->GetInfo();
        result.UsedMemoryCount = info.UsedMemoryCount;
        result.UsedMemoryUsage = info.UsedMemoryUsage;
        result.FreeMemoryUsage = info.FreeMemoryUsage;
        return result;
    }

    const char* SlabMemoryAllocator::GetTypename() const {
        return "SlabMemoryAllocator";
    }

    // SlabCacheAllocator

    SlabCacheAllocator::SlabCacheAllocator(uint64_t maxSlabSize,
                                           uint64_t minSlabSize,
                                           uint64_t slabAlignment,
                                           double slabFragmentationLimit,
                                           bool alwaysPrefetchSlab,
                                           double slabGrowthFactor,
                                           std::unique_ptr<MemoryAllocator> memoryAllocator)
        : MemoryAllocator(std::move(memoryAllocator)),
          mMaxSlabSize(maxSlabSize),
          mMinSlabSize(minSlabSize),
          mSlabAlignment(slabAlignment),
          mSlabFragmentationLimit(slabFragmentationLimit),
          mAllowSlabPrefetch(alwaysPrefetchSlab),
          mSlabGrowthFactor(slabGrowthFactor) {
        ASSERT(IsPowerOfTwo(mMaxSlabSize));
        ASSERT(mSlabGrowthFactor >= 1);
    }

    SlabCacheAllocator::~SlabCacheAllocator() {
        mSizeCache.RemoveAndDeleteAll();
        mSlabAllocators.RemoveAndDeleteAll();
    }

    std::unique_ptr<MemoryAllocation> SlabCacheAllocator::TryAllocateMemory(
        const MEMORY_ALLOCATION_REQUEST& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabCacheAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_CHECK_NONZERO(request.SizeInBytes);

        const uint64_t blockSize = AlignTo(request.SizeInBytes, request.Alignment);

        // Create a slab allocator for the new entry.
        auto entry = mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(blockSize),
                                            request.CacheSize);
        SlabMemoryAllocator* slabAllocator = entry->GetValue().pSlabAllocator;
        if (slabAllocator == nullptr) {
            slabAllocator = new SlabMemoryAllocator(
                blockSize, mMaxSlabSize, mMinSlabSize, mSlabAlignment,
                mSlabFragmentationLimit, mAllowSlabPrefetch, mSlabGrowthFactor, GetNextInChain());
            entry->GetValue().pSlabAllocator = slabAllocator;
            mSlabAllocators.Append(slabAllocator);
        }

        ASSERT(slabAllocator != nullptr);

        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(slabAllocator->TryAllocateMemory(request), subAllocation);

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

    MEMORY_ALLOCATOR_INFO SlabCacheAllocator::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);

        MEMORY_ALLOCATOR_INFO result = {};
        for (const auto& entry : mSizeCache) {
            const MEMORY_ALLOCATOR_INFO& info = entry->GetValue().pSlabAllocator->GetInfo();
            result.UsedBlockCount += info.UsedBlockCount;
            result.UsedBlockUsage += info.UsedBlockUsage;
        }

        // Memory allocator is common across slab allocators.
        const MEMORY_ALLOCATOR_INFO& info = GetNextInChain()->GetInfo();
        result.FreeMemoryUsage = info.FreeMemoryUsage;
        result.UsedMemoryCount = info.UsedMemoryCount;
        result.UsedMemoryUsage = info.UsedMemoryUsage;

        return result;
    }

    uint64_t SlabCacheAllocator::GetMemorySize() const {
        return GetNextInChain()->GetMemorySize();
    }

    const char* SlabCacheAllocator::GetTypename() const {
        return "SlabCacheAllocator";
    }

}  // namespace gpgmm
