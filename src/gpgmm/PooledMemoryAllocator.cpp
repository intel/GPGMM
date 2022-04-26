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

#include "gpgmm/PooledMemoryAllocator.h"

#include "gpgmm/Debug.h"
#include "gpgmm/MemoryPool.h"
#include "gpgmm/common/Assert.h"

namespace gpgmm {

    PooledMemoryAllocator::PooledMemoryAllocator(std::unique_ptr<MemoryAllocator> memoryAllocator,
                                                 MemoryPool* pool)
        : MemoryAllocator(std::move(memoryAllocator)), mPool(pool) {
        ASSERT(mPool != nullptr);
    }

    std::unique_ptr<MemoryAllocation> PooledMemoryAllocator::TryAllocateMemory(
        uint64_t requestSize,
        uint64_t alignment,
        bool neverAllocate,
        bool cacheSize,
        bool prefetchMemory) {
        TRACE_EVENT0(TraceEventCategory::Default, "PooledMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        std::unique_ptr<MemoryAllocation> allocation = mPool->AcquireFromPool();
        if (allocation == nullptr) {
            GPGMM_TRY_ASSIGN(GetFirstChild()->TryAllocateMemory(
                                 requestSize, alignment, neverAllocate, cacheSize, prefetchMemory),
                             allocation);
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

        mPool->ReturnToPool(std::make_unique<MemoryAllocation>(GetFirstChild(), memory));
    }

    uint64_t PooledMemoryAllocator::GetMemorySize() const {
        return mPool->GetMemorySize();
    }

    const char* PooledMemoryAllocator::GetTypename() const {
        return "PooledMemoryAllocator";
    }

}  // namespace gpgmm
