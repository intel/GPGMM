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
                                               ScopedRef<MemoryAllocatorBase> memoryAllocator)
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

        GPGMM_RETURN_IF_ERROR(ValidateRequest(request));

        // Round allocation size to nearest power-of-two.
        const uint64_t allocationSize = UpperPowerOfTwo(request.SizeInBytes);

        // Request cannot exceed memory size.
        GPGMM_RETURN_ERROR_IF(this, allocationSize > mMemorySize,
                              "Allocation size exceeds memory size", ErrorCode::kSizeExceeded);

        // Attempt to sub-allocate a block of the requested size.
        std::unique_ptr<MemoryAllocationBase> subAllocation;
        GPGMM_TRY_ASSIGN(
            TrySubAllocateMemory(
                &mBuddyBlockAllocator, allocationSize, request.Alignment, request.NeverAllocate,
                [&](const auto& block) -> ResultOrError<std::unique_ptr<MemoryAllocationBase>> {
                    const uint64_t memoryIndex = GetMemoryIndex(block->Offset);

                    std::unique_ptr<MemoryAllocationBase> memoryAllocation;
                    GPGMM_TRY_ASSIGN(mUsedPool.AcquireFromPool(memoryIndex), memoryAllocation);

                    // No existing, allocate new memory for the block.
                    if (memoryAllocation == nullptr) {
                        MemoryAllocationRequest newRequest = request;
                        newRequest.SizeInBytes = mMemorySize;
                        newRequest.Alignment = mMemoryAlignment;
                        GPGMM_TRY_ASSIGN(GetNextInChain()->TryAllocateMemory(newRequest),
                                         memoryAllocation);
                    }

                    const MemoryAllocationBase buddyAllocation = *memoryAllocation;
                    mUsedPool.ReturnToPool(std::move(memoryAllocation), memoryIndex);

                    return std::make_unique<MemoryAllocationBase>(buddyAllocation);
                }),
            subAllocation);

        MemoryBlock* block = subAllocation->GetBlock();
        mStats.UsedBlockCount++;
        mStats.UsedBlockUsage += block->Size;

        // Memory allocation offset is always memory-relative.
        const uint64_t memoryOffset = block->Offset % mMemorySize;

        subAllocation->SetOffset(memoryOffset);
        subAllocation->SetMethod(AllocationMethod::kSubAllocated);
        subAllocation->SetAllocator(this);

        return subAllocation;
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

        auto result = mUsedPool.AcquireFromPool(memoryIndex);
        ASSERT(result.IsSuccess());

        std::unique_ptr<MemoryAllocationBase> allocation = result.AcquireResult();

        MemoryBase* memory = allocation->GetMemory();
        ASSERT(memory != nullptr);

        if (memory->Unref()) {
            GetNextInChain()->DeallocateMemory(std::move(allocation));
        } else {
            mUsedPool.ReturnToPool(std::move(allocation), memoryIndex);
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
