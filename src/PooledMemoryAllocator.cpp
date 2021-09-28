// Copyright 2020 The Dawn Authors
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

#include "src/PooledMemoryAllocator.h"
#include "common/Assert.h"

namespace gpgmm {

    PooledMemoryAllocator::PooledMemoryAllocator(MemoryAllocator* memoryAllocator)
        : mMemoryAllocator(memoryAllocator) {
    }

    PooledMemoryAllocator::~PooledMemoryAllocator() {
        ASSERT(GetPoolSizeForTesting() == 0);
    }

    void PooledMemoryAllocator::ReleaseMemory() {
        for (auto& allocation : mPool) {
            ASSERT(allocation != nullptr);
            mMemoryAllocator->DeallocateMemory(allocation.release());
        }

        mPool.clear();
    }

    std::unique_ptr<MemoryAllocation> PooledMemoryAllocator::AllocateMemory(uint64_t size,
                                                                            uint64_t alignment) {
        // Pooled memory is LIFO because memory can be evicted by LRU. However, this means
        // pooling is disabled in-frame when the memory is still pending. For high in-frame
        // memory users, FIFO might be preferable when memory consumption is a higher priority.
        std::unique_ptr<MemoryAllocation> allocation;
        if (!mPool.empty()) {
            allocation = std::move(mPool.front());
            mPool.pop_front();
        }

        if (allocation == nullptr) {
            allocation = mMemoryAllocator->AllocateMemory(size, alignment);
        }

        return allocation;
    }

    void PooledMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        mPool.push_front(std::unique_ptr<MemoryAllocation>(allocation));
    }

    uint64_t PooledMemoryAllocator::GetMemorySize() const {
        return mMemoryAllocator->GetMemorySize();
    }

    uint64_t PooledMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAllocator->GetMemoryAlignment();
    }

    uint64_t PooledMemoryAllocator::GetPoolSizeForTesting() const {
        return mPool.size();
    }
}  // namespace gpgmm
