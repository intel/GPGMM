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

#include "gpgmm/common/PooledMemoryAllocator.h"

#include "gpgmm/common/LIFOMemoryPool.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm {

    PooledMemoryAllocator::PooledMemoryAllocator(uint64_t memorySize,
                                                 uint64_t memoryAlignment,
                                                 std::unique_ptr<MemoryAllocator> memoryAllocator)
        : MemoryAllocator(std::move(memoryAllocator)),
          mPool(new LIFOMemoryPool(memorySize)),
          mMemoryAlignment(memoryAlignment) {
        ASSERT(IsAligned(memorySize, mMemoryAlignment));
    }

    PooledMemoryAllocator::~PooledMemoryAllocator() {
        mPool->ReleasePool(kInvalidSize);
    }

    std::unique_ptr<MemoryAllocation> PooledMemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "PooledMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_INVALID_IF(!ValidateRequest(request));

        MemoryAllocation allocation = mPool->AcquireFromPool();
        if (allocation == GPGMM_ERROR_INVALID_ALLOCATION) {
            std::unique_ptr<MemoryAllocation> allocationPtr;
            GPGMM_TRY_ASSIGN(GetNextInChain()->TryAllocateMemory(request), allocationPtr);
            allocation = *allocationPtr;
        } else {
            mInfo.FreeMemoryUsage -= allocation.GetSize();
        }

        mInfo.UsedMemoryCount++;
        mInfo.UsedMemoryUsage += allocation.GetSize();

        MemoryBase* memory = allocation.GetMemory();
        ASSERT(memory != nullptr);

        return std::make_unique<MemoryAllocation>(this, memory, allocation.GetRequestSize());
    }

    void PooledMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "PooledMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        const uint64_t& allocationSize = allocation->GetSize();
        mInfo.FreeMemoryUsage += allocationSize;
        mInfo.UsedMemoryCount--;
        mInfo.UsedMemoryUsage -= allocationSize;

        MemoryBase* memory = allocation->GetMemory();
        ASSERT(memory != nullptr);

        mPool->ReturnToPool(
            MemoryAllocation(GetNextInChain(), memory, allocation->GetRequestSize()));
    }

    uint64_t PooledMemoryAllocator::ReleaseMemory(uint64_t bytesToRelease) {
        const uint64_t bytesReleased = mPool->ReleasePool(bytesToRelease);
        mInfo.FreeMemoryUsage -= bytesReleased;
        return bytesReleased;
    }

    uint64_t PooledMemoryAllocator::GetMemorySize() const {
        return mPool->GetMemorySize();
    }

    uint64_t PooledMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAlignment;
    }

    const char* PooledMemoryAllocator::GetTypename() const {
        return "PooledMemoryAllocator";
    }

}  // namespace gpgmm
