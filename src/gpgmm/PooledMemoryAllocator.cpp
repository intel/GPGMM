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

#include "gpgmm/MemoryPool.h"
#include "gpgmm/common/Assert.h"

namespace gpgmm {

    PooledMemoryAllocator::PooledMemoryAllocator(std::unique_ptr<MemoryAllocator> memoryAllocator,
                                                 MemoryPool* pool)
        : MemoryAllocator(std::move(memoryAllocator)), mPool(pool) {
        ASSERT(mPool != nullptr);
    }

    std::unique_ptr<MemoryAllocation> PooledMemoryAllocator::TryAllocateMemory(
        uint64_t allocationSize,
        uint64_t alignment,
        bool neverAllocate,
        bool cacheSize) {
        std::unique_ptr<MemoryAllocation> allocation = mPool->AcquireFromPool();
        if (allocation == nullptr) {
            GPGMM_TRY_ASSIGN(GetFirstChild()->TryAllocateMemory(allocationSize, alignment,
                                                                neverAllocate, cacheSize),
                             allocation);
        }

        return allocation;
    }

    void PooledMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        mPool->ReturnToPool(std::unique_ptr<MemoryAllocation>(allocation));
    }
}  // namespace gpgmm
