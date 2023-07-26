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

#include "gpgmm/common/BuddyMemoryAllocator.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/Memory.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm {

    BuddyMemoryAllocator::BuddyMemoryAllocator(uint64_t systemSize,
                                               uint64_t memorySize,
                                               uint64_t memoryAlignment,
                                               std::unique_ptr<MemoryAllocatorBase> memoryAllocator)
        : MemoryAllocatorBase(std::move(memoryAllocator)),
          mMemorySize(memorySize),
          mMemoryAlignment(memoryAlignment),
          mBuddyBlockAllocator(systemSize),
          mUsedPool(mMemorySize) {
        ASSERT(mMemorySize <= systemSize);
        ASSERT(IsPowerOfTwo(mMemoryAlignment));
        ASSERT(IsAligned(systemSize, mMemorySize));
        ASSERT(IsAligned(mMemorySize, mMemoryAlignment));
    }

    uint64_t BuddyMemoryAllocator::GetMemoryIndex(uint64_t offset) const {
        ASSERT(offset != kInvalidOffset);
        return static_cast<uint64_t>(SafeDivide(offset, mMemorySize));
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> BuddyMemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "BuddyMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_RETURN_INVALID_IF(!ValidateRequest(request));

        // Round allocation size to nearest power-of-two.
        const uint64_t allocationSize = NextPowerOfTwo(request.SizeInBytes);

        // Request cannot exceed memory size.
        GPGMM_RETURN_INVALID_IF(allocationSize > mMemorySize);

        // Attempt to sub-allocate a block of the requested size.
        std::unique_ptr<MemoryAllocationBase> subAllocation;
        GPGMM_TRY_ASSIGN(
            TrySubAllocateMemory(
                &mBuddyBlockAllocator, allocationSize, request.Alignment, request.NeverAllocate,
                [&](const auto& block) -> ResultOrError<MemoryBase*> {
                    const uint64_t memoryIndex = GetMemoryIndex(block->Offset);
                    MemoryAllocationBase memoryAllocation = mUsedPool.AcquireFromPool(memoryIndex);

                    // No existing, allocate new memory for the block.
                    if (memoryAllocation == GPGMM_INVALID_ALLOCATION) {
                        MemoryAllocationRequest newRequest = request;
                        newRequest.SizeInBytes = mMemorySize;
                        newRequest.Alignment = mMemoryAlignment;

                        ResultOrError<std::unique_ptr<MemoryAllocationBase>>
                            memoryAllocationResult =
                                GetNextInChain()->TryAllocateMemory(newRequest);
                        if (!memoryAllocationResult.IsSuccess()) {
                            return memoryAllocationResult.GetErrorCode();
                        }

                        memoryAllocation = *memoryAllocationResult.AcquireResult();
                    }

                    MemoryBase* memory = memoryAllocation.GetMemory();
                    mUsedPool.ReturnToPool(memoryAllocation, memoryIndex);

                    return memory;
                }),
            subAllocation);

        MemoryBlock* block = subAllocation->GetBlock();
        mStats.UsedBlockCount++;
        mStats.UsedBlockUsage += block->Size;

        // Memory allocation offset is always memory-relative.
        const uint64_t memoryOffset = block->Offset % mMemorySize;

        return std::make_unique<MemoryAllocationBase>(
            /*allocator*/ this, subAllocation->GetMemory(), memoryOffset,
            AllocationMethod::kSubAllocated, block, request.SizeInBytes);
    }

    void BuddyMemoryAllocator::DeallocateMemory(
        std::unique_ptr<MemoryAllocationBase> subAllocation) {
        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "BuddyMemoryAllocator.DeallocateMemory");

        ASSERT(subAllocation != nullptr);

        mStats.UsedBlockCount--;
        mStats.UsedBlockUsage -= subAllocation->GetSize();

        const uint64_t memoryIndex = GetMemoryIndex(subAllocation->GetBlock()->Offset);

        mBuddyBlockAllocator.DeallocateBlock(subAllocation->GetBlock());

        MemoryAllocationBase memoryAllocation = mUsedPool.AcquireFromPool(memoryIndex);

        MemoryBase* memory = memoryAllocation.GetMemory();
        ASSERT(memory != nullptr);

        if (memory->Unref()) {
            GetNextInChain()->DeallocateMemory(
                std::make_unique<MemoryAllocationBase>(memoryAllocation));
        } else {
            mUsedPool.ReturnToPool(memoryAllocation, memoryIndex);
        }
    }

    uint64_t BuddyMemoryAllocator::GetMemorySize() const {
        return mMemorySize;
    }

    uint64_t BuddyMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAlignment;
    }

    MemoryAllocatorStats BuddyMemoryAllocator::GetStats() const {
        std::lock_guard<std::mutex> lock(mMutex);

        MemoryAllocatorStats result = mStats;
        const MemoryAllocatorStats& memoryInfo = GetNextInChain()->GetStats();
        result.UsedMemoryCount = memoryInfo.UsedMemoryCount;
        result.UsedMemoryUsage = memoryInfo.UsedMemoryUsage;
        result.FreeMemoryUsage = memoryInfo.FreeMemoryUsage;
        return result;
    }

}  // namespace gpgmm
