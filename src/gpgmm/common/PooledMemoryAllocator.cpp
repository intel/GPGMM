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

#include "gpgmm/common/PooledMemoryAllocator.h"

#include "gpgmm/common/LIFOMemoryPool.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm {

    PooledMemoryAllocator::PooledMemoryAllocator(
        uint64_t memorySize,
        uint64_t memoryAlignment,
        std::unique_ptr<MemoryAllocatorBase> memoryAllocator)
        : MemoryAllocatorBase(std::move(memoryAllocator)),
          mPool(new LIFOMemoryPool(memorySize)),
          mMemoryAlignment(memoryAlignment) {
        ASSERT(IsAligned(memorySize, mMemoryAlignment));
    }

    PooledMemoryAllocator::~PooledMemoryAllocator() {
        mPool->ReleasePool(kInvalidSize);
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> PooledMemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "PooledMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_RETURN_IF_ERROR(ValidateRequest(request));

        MemoryAllocationBase allocation = mPool->AcquireFromPool(kInvalidIndex);
        if (allocation == GPGMM_INVALID_ALLOCATION) {
            MemoryAllocationRequest memoryRequest = request;
            memoryRequest.Alignment = mMemoryAlignment;
            memoryRequest.SizeInBytes = AlignTo(request.SizeInBytes, mMemoryAlignment);

            std::unique_ptr<MemoryAllocationBase> allocationPtr;
            GPGMM_TRY_ASSIGN(GetNextInChain()->TryAllocateMemory(memoryRequest), allocationPtr);
            allocation = *allocationPtr;
        } else {
            mStats.FreeMemoryUsage -= allocation.GetSize();
        }

        mStats.UsedMemoryCount++;
        mStats.UsedMemoryUsage += allocation.GetSize();

        MemoryBase* memory = allocation.GetMemory();
        ASSERT(memory != nullptr);

        return std::make_unique<MemoryAllocationBase>(this, memory, allocation.GetRequestSize());
    }

    void PooledMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "PooledMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        const uint64_t& allocationSize = allocation->GetSize();
        mStats.FreeMemoryUsage += allocationSize;
        mStats.UsedMemoryCount--;
        mStats.UsedMemoryUsage -= allocationSize;

        MemoryBase* memory = allocation->GetMemory();
        ASSERT(memory != nullptr);

        mPool->ReturnToPool(
            MemoryAllocationBase(GetNextInChain(), memory, allocation->GetRequestSize()),
            kInvalidIndex);
    }

    uint64_t PooledMemoryAllocator::ReleaseMemory(uint64_t bytesToRelease) {
        const uint64_t bytesReleased = mPool->ReleasePool(bytesToRelease);
        mStats.FreeMemoryUsage -= bytesReleased;
        return bytesReleased;
    }

    uint64_t PooledMemoryAllocator::GetMemorySize() const {
        return mPool->GetMemorySize();
    }

    uint64_t PooledMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAlignment;
    }

}  // namespace gpgmm
