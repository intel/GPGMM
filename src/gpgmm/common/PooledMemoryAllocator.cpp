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

#include "gpgmm/common/Debug.h"
#include "gpgmm/common/LIFOMemoryPool.h"
#include "gpgmm/utils/Assert.h"

namespace gpgmm {

    PooledMemoryAllocator::PooledMemoryAllocator(uint64_t memorySize,
                                                 std::unique_ptr<MemoryAllocator> memoryAllocator)
        : MemoryAllocator(std::move(memoryAllocator)), mPool(new LIFOMemoryPool(memorySize)) {
        ASSERT(mPool != nullptr);
    }

    PooledMemoryAllocator::~PooledMemoryAllocator() {
        mPool->ReleasePool();
    }

    std::unique_ptr<MemoryAllocation> PooledMemoryAllocator::TryAllocateMemory(
        const MEMORY_ALLOCATION_REQUEST& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "PooledMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        std::unique_ptr<MemoryAllocation> allocation = mPool->AcquireFromPool();
        if (allocation == nullptr) {
            GPGMM_TRY_ASSIGN(GetNextInChain()->TryAllocateMemory(request), allocation);
        } else {
            mInfo.FreeMemoryUsage -= allocation->GetSize();
        }

        mInfo.UsedMemoryCount++;
        mInfo.UsedMemoryUsage += allocation->GetSize();

        MemoryBase* memory = allocation->GetMemory();
        ASSERT(memory != nullptr);

        return std::make_unique<MemoryAllocation>(this, memory);
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

        mPool->ReturnToPool(std::make_unique<MemoryAllocation>(GetNextInChain(), memory));
    }

    void PooledMemoryAllocator::ReleaseMemory() {
        mPool->ReleasePool();
    }

    uint64_t PooledMemoryAllocator::GetMemorySize() const {
        return mPool->GetMemorySize();
    }

    const char* PooledMemoryAllocator::GetTypename() const {
        return "PooledMemoryAllocator";
    }

}  // namespace gpgmm
