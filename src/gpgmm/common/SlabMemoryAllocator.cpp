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

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/Memory.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Utils.h"

#include <algorithm>  // std::max

namespace gpgmm {

    // Disables pre-fetching of memory objects that have too little space.
    constexpr static uint64_t kSlabPrefetchMinBlockCount = 4u;

    // Disables pre-fetching of memory objects that are under-utilizied.
    constexpr static double kSlabPrefetchUsageThreshold = 0.50;

    // Disables pre-fetching of memory objects that are too large.
    // Larger memory objects require more time on the device to allocate memory and could block a
    // subsequent allocation request using the device with a previously allocated memory object.
    // This threshold is used to restrict pre-fetching to smaller memory blocks to minimize the
    // the amount of time required for the application to be busy or not waiting on the next
    // allocation.
    constexpr static uint64_t kSlabPrefetchMemorySizeThreshold = 64u * 1024 * 1024;

    // Coverage is the fraction of total misses that should be eliminated because of pre-fetching.
    // If coverage goes below the specified min. coverage threshold, a warning event will be
    // emitted.
    constexpr static double kPrefetchCoverageWarnMinThreshold = 0.50;

    // Slab contains a free-list of blocks and a reference to underlying memory.
    struct Slab {
        Slab(uint64_t blockCount, uint64_t blockSize, uint64_t indexInList)
            : Allocator(blockCount, blockSize), IndexInList(indexInList) {
        }

        uint64_t GetBlockCount() const {
            return Allocator.GetBlockCount();
        }

        bool IsFull() const {
            return UsedBlocksPerSlab == Allocator.GetBlockCount();
        }

        bool IsEmpty() const {
            return UsedBlocksPerSlab == 0;
        }

        double GetUsedPercent() const {
            return SafeDivide(UsedBlocksPerSlab, Allocator.GetBlockCount());
        }

        void ReleaseBlocks() {
            return Allocator.ReleaseBlocks();
        }

        SlabBlockAllocator Allocator;
        uint64_t UsedBlocksPerSlab = 0;
        MemoryAllocation Allocation;
        uint64_t IndexInList = kInvalidIndex;
        uint64_t IndexInCache = kInvalidIndex;
    };

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
        ASSERT(IsPowerOfTwo(mSlabAlignment));
        ASSERT(mMemoryAllocator != nullptr);
        ASSERT(mSlabGrowthFactor >= 1);
        ASSERT(IsAligned(mMaxSlabSize, mSlabAlignment));
        ASSERT(IsAligned(mMinSlabSize, mSlabAlignment));
        ASSERT(blockSize <= mMaxSlabSize);
    }

    SlabMemoryAllocator::~SlabMemoryAllocator() {
        if (mNextSlabAllocationEvent != nullptr) {
            mNextSlabAllocationEvent->Wait();
            mMemoryAllocator->DeallocateMemory(mNextSlabAllocationEvent->AcquireAllocation());
        }

        for (SlabCache& cache : mCaches) {
            for (auto& slab : cache.FreeList) {
                slab.ReleaseBlocks();
            }

            for (auto& slab : cache.FullList) {
                slab.ReleaseBlocks();
            }
        }
    }

    // Returns a new slab size of a power-of-two value.
    uint64_t SlabMemoryAllocator::ComputeSlabSize(uint64_t requestSize,
                                                  uint64_t baseSlabSize,
                                                  uint64_t availableForAllocation) const {
        ASSERT(requestSize <= mBlockSize);

        uint64_t slabSize = baseSlabSize;

        // If the left over empty space is less than |mSlabFragmentationLimit| x slab size,
        // then the fragmentation is acceptable and we are done. For example, a 4MB slab and and a
        // 512KB block fits exactly 8 blocks with no wasted space. But a 3MB block has 1MB worth of
        // empty space leftover which exceeds |mSlabFragmentationLimit| x slab size or 500KB.
        const uint64_t fragmentedBytes = mBlockSize - requestSize;
        while (requestSize > slabSize || fragmentedBytes > (mSlabFragmentationLimit * slabSize)) {
            slabSize *= 2;
        }

        slabSize = NextPowerOfTwo(slabSize);

        // If the larger slab excceeds available memory, re-use a slab instead.
        // Otherwise, creating a larger slab will page-out smaller slabs.
        if (availableForAllocation < slabSize) {
            const uint64_t slabSizeUnderBudget = FindNextFreeSlabOfSize(requestSize);
            if (slabSizeUnderBudget == kInvalidSize) {
                DebugEvent(GetTypename()) << "Slab size exceeds available memory: " << slabSize
                                          << " vs " << availableForAllocation << " bytes.";
                return kInvalidSize;
            }

            slabSize = slabSizeUnderBudget;
        }

        return slabSize;
    }

    uint64_t SlabMemoryAllocator::FindNextFreeSlabOfSize(uint64_t slabSize) const {
        // Larger slabs are used first.
        for (uint64_t cacheIndex = 0; cacheIndex < mCaches.size(); cacheIndex++) {
            const SlabCache* cache = &mCaches[cacheIndex];
            ASSERT(cache != nullptr);

            if (cache->FreeList.empty()) {
                continue;
            }

            const Slab& freeSlab = cache->FreeList.back();

            // Slab is not free if only the block exists.
            if (freeSlab.Allocation.GetMemory() == nullptr) {
                continue;
            }

            if (freeSlab.Allocation.GetSize() >= slabSize) {
                return freeSlab.Allocation.GetSize();
            }
        }

        return kInvalidSize;
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
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_INVALID_IF(request.SizeInBytes > mBlockSize);

        uint64_t slabSize =
            ComputeSlabSize(request.SizeInBytes, std::max(mMinSlabSize, mLastUsedSlabSize),
                            request.AvailableForAllocation);

        // Slab cannot exceed memory size.
        GPGMM_INVALID_IF(slabSize > mMaxSlabSize);

        // Get or create the cache containing slabs of the slab size.
        SlabCache* pCache = GetOrCreateCache(slabSize);
        ASSERT(pCache != nullptr);

        // Push a new free slab at free-list HEAD.
        if (pCache->FreeList.empty()) {
            // Get the next free slab.
            if (mLastUsedSlabSize > 0) {
                uint64_t newSlabSize = ComputeSlabSize(
                    request.SizeInBytes, static_cast<uint64_t>(slabSize * mSlabGrowthFactor),
                    request.AvailableForAllocation);
                GPGMM_INVALID_IF(newSlabSize == kInvalidSize);

                // If the new slab size exceeds the limit, then re-use the previous, smaller size.
                if (newSlabSize > mMaxSlabSize) {
                    newSlabSize = slabSize;
                }

                // If the new slab size is not larger then the total size of full slabs, then re-use
                // the previous, smaller size. Otherwise, the larger slab would likely never be
                // fully used. For example, assuming 2x growth, 2x2MB slabs need to be fully used
                // before creating a 4MB one. If not, half of the growth (or 2MB) could be wasted.
                const uint64_t numOfSlabsInNewSlabSize = newSlabSize / slabSize;
                if (pCache->FullList.occupied_size() < numOfSlabsInNewSlabSize) {
                    newSlabSize = slabSize;
                }

                if (newSlabSize > slabSize) {
                    pCache = GetOrCreateCache(newSlabSize);
                    slabSize = newSlabSize;
                }
            }

            pCache->FreeList.emplace_back(static_cast<uint64_t>(SafeDivide(slabSize, mBlockSize)),
                                          mBlockSize, pCache->FreeList.size());

            pCache->FreeList.back().IndexInCache = pCache->Slabs.size();
            pCache->Slabs.push_back(&pCache->FreeList.back());
        }

        Slab* pFreeSlab = &pCache->FreeList.back();
        ASSERT(pFreeSlab != nullptr);
        ASSERT(!pFreeSlab->IsFull());

        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(
            TrySubAllocateMemory(
                &pFreeSlab->Allocator, mBlockSize, request.Alignment, request.NeverAllocate,
                [&](const auto& block) -> MemoryBase* {
                    // Re-use memory from the free slab.
                    if (pFreeSlab->Allocation.GetMemory() != nullptr) {
                        return pFreeSlab->Allocation.GetMemory();
                    }

                    // Or use pre-fetched memory if possible. Else, throw it away and create a new
                    // slab.
                    if (mNextSlabAllocationEvent != nullptr) {
                        // Resolve the pending pre-fetched allocation.
                        mNextSlabAllocationEvent->Wait();
                        std::unique_ptr<MemoryAllocation> prefetchedSlabAllocation =
                            mNextSlabAllocationEvent->AcquireAllocation();
                        mNextSlabAllocationEvent.reset();

                        // Assign pre-fetched memory to the slab.
                        if (prefetchedSlabAllocation != nullptr &&
                            prefetchedSlabAllocation->GetSize() == slabSize) {
                            pFreeSlab->Allocation = *prefetchedSlabAllocation;
                            mInfo.PrefetchedMemoryMissesEliminated++;
                            return pFreeSlab->Allocation.GetMemory();
                        }

                        if (prefetchedSlabAllocation != nullptr) {
                            DebugEvent(GetTypename(), EventMessageId::PrefetchFailed)
                                << "Pre-fetch slab memory is incompatible (" << slabSize << " vs "
                                << prefetchedSlabAllocation->GetSize() << " bytes.";
                        }

                        mInfo.PrefetchedMemoryMisses++;

                        mMemoryAllocator->DeallocateMemory(std::move(prefetchedSlabAllocation));
                    }

                    // Create memory of specified slab size.
                    MemoryAllocationRequest newSlabRequest = request;
                    newSlabRequest.SizeInBytes = slabSize;
                    newSlabRequest.Alignment = mSlabAlignment;

                    std::unique_ptr<MemoryAllocation> slabAllocation;
                    GPGMM_TRY_ASSIGN(mMemoryAllocator->TryAllocateMemory(newSlabRequest),
                                     slabAllocation);

                    pFreeSlab->Allocation = *slabAllocation;

                    return pFreeSlab->Allocation.GetMemory();
                }),
            subAllocation);

        // Slab is referenced seperately from its underlying memory because the memory used by the
        // slab could be already allocated by another allocator. Only once the last block on the
        // slab is deallocated, does the slab release its memory.
        pFreeSlab->UsedBlocksPerSlab++;

        // Remember the last allocated slab size so if a subsequent allocation requests a new slab,
        // the next slab size will be larger than the previous slab size.
        mLastUsedSlabSize = slabSize;

        // Disallow pre-fetching when coverage goes below threshold.
        // TODO: Consider re-allowing when AlwaysCacheSize=true.
        const bool allowSlabPrefetch = mAllowSlabPrefetch && IsPrefetchCoverageBelowThreshold();

        // Prefetch memory for future slab.
        //
        // This check is overly conservative since waiting for the device to retrieve pre-fetched
        // memory could block the next allocation from being created until the device becomes free.
        //
        // TODO: Measure if the slab allocation time remaining exceeds the prefetch memory task
        // time before deciding to prefetch.
        if ((request.AlwaysPrefetch || allowSlabPrefetch) && mNextSlabAllocationEvent == nullptr &&
            pFreeSlab->GetUsedPercent() >= kSlabPrefetchUsageThreshold &&
            pFreeSlab->GetBlockCount() >= kSlabPrefetchMinBlockCount) {
            // If a subsequent TryAllocateMemory() uses a request size different than the current
            // request size, memory required for the next slab could be the wrong size. If so,
            // pre-fetching did not pay off and the pre-fetched memory will be de-allocated instead.
            uint64_t nextSlabSize = ComputeSlabSize(
                request.SizeInBytes, static_cast<uint64_t>(mLastUsedSlabSize * mSlabGrowthFactor),
                request.AvailableForAllocation);

            // If the next slab size exceeds the limit, then re-use the previous, smaller size.
            if (nextSlabSize > mMaxSlabSize) {
                nextSlabSize = mLastUsedSlabSize;
            }

            // If under growth phase (and accounting that the current slab will soon become
            // full), reset the slab size back to the last size. Otherwise, the pre-fetch will
            // always miss the cache since the larger slab cannot be used until enough smaller slabs
            // become full first.
            const uint64_t numOfSlabsInNextSlabSize = nextSlabSize / mLastUsedSlabSize;
            if (pCache->FullList.occupied_size() + 1 < numOfSlabsInNextSlabSize) {
                nextSlabSize = mLastUsedSlabSize;
            }

            if (nextSlabSize <= kSlabPrefetchMemorySizeThreshold) {
                MemoryAllocationRequest newSlabRequest = request;
                newSlabRequest.SizeInBytes = nextSlabSize;
                newSlabRequest.Alignment = mSlabAlignment;
                newSlabRequest.AlwaysPrefetch = false;

                mNextSlabAllocationEvent = mMemoryAllocator->TryAllocateMemoryAsync(newSlabRequest);
            }
        }

        // If the slab is now full, move it to the full-list so it does not remain the free-list
        // where de-allocate could mistakenly remove it from the wrong list.
        if (pFreeSlab->IsFull()) {
            pFreeSlab = MoveSlabInCache(pFreeSlab, pCache, /*pSrcList*/ &pCache->FreeList,
                                        /*pDstList*/ &pCache->FullList);
        }

        // Assign the containing slab to the block so DeallocateMemory() knows how to release it.
        SlabBlock* blockInSlab = static_cast<SlabBlock*>(subAllocation->GetBlock());
        blockInSlab->ppSlab = &pCache->Slabs[pFreeSlab->IndexInCache];

        // Since the slab's block could reside in another allocated block, the allocation
        // offset must be made relative to the slab's underlying memory and not the slab itself.
        const uint64_t offsetFromMemory = pFreeSlab->Allocation.GetOffset() + blockInSlab->Offset;

        mInfo.UsedBlockCount++;
        mInfo.UsedBlockUsage += blockInSlab->Size;

        return std::make_unique<MemoryAllocation>(this, subAllocation->GetMemory(),
                                                  offsetFromMemory, AllocationMethod::kSubAllocated,
                                                  blockInSlab, request.SizeInBytes);
    }

    void SlabMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> subAllocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        SlabBlock* blockInSlab = static_cast<SlabBlock*>(subAllocation->GetBlock());
        ASSERT(blockInSlab != nullptr);

        Slab* pSlab = *(blockInSlab->ppSlab);
        ASSERT(pSlab != nullptr);

        SlabCache* pCache = GetOrCreateCache(pSlab->Allocation.GetSize());
        ASSERT(pCache != nullptr);

        // Move the slab from the full-list to free-list.
        if (pSlab->IsFull()) {
            pSlab = MoveSlabInCache(pSlab, pCache, /*pSrcList*/ &pCache->FullList,
                                    /*pDstList*/ &pCache->FreeList);
        }

        mInfo.UsedBlockCount--;
        mInfo.UsedBlockUsage -= blockInSlab->Size;

        pSlab->Allocator.DeallocateBlock(blockInSlab);
        pSlab->UsedBlocksPerSlab--;

        MemoryBase* slabMemory = subAllocation->GetMemory();
        ASSERT(slabMemory != nullptr);

        slabMemory->RemoveSubAllocationRef();

        if (pSlab->IsEmpty()) {
            mMemoryAllocator->DeallocateMemory(
                std::make_unique<MemoryAllocation>(pSlab->Allocation));
            pSlab->Allocation = {};  // Invalidate it
        }
    }

    Slab* SlabMemoryAllocator::MoveSlabInCache(Slab* pSlab,
                                               SlabCache* pCache,
                                               StableList<Slab>* pSrcList,
                                               StableList<Slab>* pDstList) {
        const uint64_t srcIndex = pSlab->IndexInList;
        pSlab->IndexInList = pDstList->size();
        pDstList->push_back(*pSlab);  // copy
        pSrcList->erase(srcIndex);
        pSlab = &pDstList->back();

        // Update the ref table
        pCache->Slabs[pSlab->IndexInCache] = pSlab;

        return pSlab;
    }

    MemoryAllocatorInfo SlabMemoryAllocator::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        MemoryAllocatorInfo result = mInfo;
        const MemoryAllocatorInfo& info = mMemoryAllocator->GetInfo();
        result.UsedMemoryCount = info.UsedMemoryCount;
        result.UsedMemoryUsage = info.UsedMemoryUsage;
        result.FreeMemoryUsage = info.FreeMemoryUsage;
        return result;
    }

    const char* SlabMemoryAllocator::GetTypename() const {
        return "SlabMemoryAllocator";
    }

    bool SlabMemoryAllocator::IsPrefetchCoverageBelowThreshold() const {
        if (mInfo.PrefetchedMemoryMissesEliminated >= mInfo.PrefetchedMemoryMisses) {
            return true;
        }

        const double currentCoverage =
            SafeDivide(mInfo.PrefetchedMemoryMissesEliminated,
                       mInfo.PrefetchedMemoryMissesEliminated + mInfo.PrefetchedMemoryMisses);
        if (currentCoverage < kPrefetchCoverageWarnMinThreshold) {
            WarnEvent(GetTypename(), EventMessageId::PrefetchFailed)
                << "Prefetch coverage is below threshold (%): " << currentCoverage * 100 << " vs "
                << kPrefetchCoverageWarnMinThreshold * 100;
            return false;
        }

        return true;
    }

    // SlabCacheAllocator

    SlabCacheAllocator::SlabCacheAllocator(uint64_t maxSlabSize,
                                           uint64_t minSlabSize,
                                           uint64_t slabAlignment,
                                           double slabFragmentationLimit,
                                           bool allowPrefetchSlab,
                                           double slabGrowthFactor,
                                           std::unique_ptr<MemoryAllocator> memoryAllocator)
        : MemoryAllocator(std::move(memoryAllocator)),
          mMaxSlabSize(maxSlabSize),
          mMinSlabSize(minSlabSize),
          mSlabAlignment(slabAlignment),
          mSlabFragmentationLimit(slabFragmentationLimit),
          mAllowSlabPrefetch(allowPrefetchSlab),
          mSlabGrowthFactor(slabGrowthFactor) {
        ASSERT(IsPowerOfTwo(mMaxSlabSize));
        ASSERT(mSlabGrowthFactor >= 1);
    }

    SlabCacheAllocator::~SlabCacheAllocator() {
        mSizeCache.clear();
    }

    std::unique_ptr<MemoryAllocation> SlabCacheAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabCacheAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_INVALID_IF(!ValidateRequest(request));

        const uint64_t blockSize = AlignTo(request.SizeInBytes, request.Alignment);
        GPGMM_INVALID_IF(blockSize > mMaxSlabSize);

        // Create a slab allocator for the new entry.
        auto entry =
            mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(blockSize), request.AlwaysCacheSize);
        SlabMemoryAllocator* slabAllocator = entry->GetValue().SlabAllocator.get();
        if (slabAllocator == nullptr) {
            entry->GetValue().SlabAllocator = std::make_unique<SlabMemoryAllocator>(
                blockSize, mMaxSlabSize, mMinSlabSize, mSlabAlignment, mSlabFragmentationLimit,
                mAllowSlabPrefetch, mSlabGrowthFactor, GetNextInChain());
            slabAllocator = entry->GetValue().SlabAllocator.get();
        }

        ASSERT(slabAllocator != nullptr);

        std::unique_ptr<MemoryAllocation> subAllocation;
        GPGMM_TRY_ASSIGN(slabAllocator->TryAllocateMemory(request), subAllocation);

        // Hold onto the cached allocator until the last allocation gets deallocated.
        entry->Ref();

        return std::make_unique<MemoryAllocation>(
            this, subAllocation->GetMemory(), subAllocation->GetOffset(),
            subAllocation->GetMethod(), subAllocation->GetBlock(), request.SizeInBytes);
    }

    void SlabCacheAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> subAllocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "SlabCacheAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        auto entry =
            mSizeCache.GetOrCreate(SlabAllocatorCacheEntry(subAllocation->GetSize()), false);
        SlabMemoryAllocator* slabAllocator = entry->GetValue().SlabAllocator.get();
        ASSERT(slabAllocator != nullptr);

        slabAllocator->DeallocateMemory(std::move(subAllocation));

        // If this is the last sub-allocation, remove the cached allocator.
        // Once |entry| goes out of scope, it will unlink itself from the cache.
        entry->Unref();
    }

    MemoryAllocatorInfo SlabCacheAllocator::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);

        MemoryAllocatorInfo result = {};
        for (const auto& entry : mSizeCache) {
            const MemoryAllocatorInfo& info = entry->GetValue().SlabAllocator->GetInfo();
            result.UsedBlockCount += info.UsedBlockCount;
            result.UsedBlockUsage += info.UsedBlockUsage;
            result.PrefetchedMemoryMisses += info.PrefetchedMemoryMisses;
            result.PrefetchedMemoryMissesEliminated += info.PrefetchedMemoryMissesEliminated;
        }

        // Memory allocator is common across slab allocators.
        const MemoryAllocatorInfo& info = GetNextInChain()->GetInfo();
        result.FreeMemoryUsage = info.FreeMemoryUsage;
        result.UsedMemoryCount = info.UsedMemoryCount;
        result.UsedMemoryUsage = info.UsedMemoryUsage;

        // Size cache is common across slab allocators.
        const CacheStats& sizeCacheStats = mSizeCache.GetStats();
        result.SizeCacheHits = sizeCacheStats.NumOfHits;
        result.SizeCacheMisses = sizeCacheStats.NumOfMisses;

        return result;
    }

    uint64_t SlabCacheAllocator::GetMemorySize() const {
        return GetNextInChain()->GetMemorySize();
    }

    const char* SlabCacheAllocator::GetTypename() const {
        return "SlabCacheAllocator";
    }

}  // namespace gpgmm
