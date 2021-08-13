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
#include "src/common/Assert.h"

namespace gpgmm {

    PooledMemoryAllocator::PooledMemoryAllocator(MemoryAllocator* memoryAllocator)
        : mMemoryAllocator(memoryAllocator) {
    }

    void PooledMemoryAllocator::Release() {
        for (auto& memory : mPool) {
            mMemoryAllocator->Deallocate(memory);
        }

        mPool.clear();
    }

    void PooledMemoryAllocator::Allocate(uint64_t size,
                                         uint64_t alignment,
                                         MemoryAllocation& allocation) {
        // Pooled memory is LIFO because memory can be evicted by LRU. However, this means
        // pooling is disabled in-frame when the memory is still pending. For high in-frame
        // memory users, FIFO might be preferable when memory consumption is a higher priority.
        if (!mPool.empty()) {
            allocation = std::move(mPool.front());
            mPool.pop_front();
        }

        if (allocation == GPGMM_INVALID_ALLOCATION) {
            mMemoryAllocator->Allocate(size, alignment, /*out*/ allocation);
        }
    }

    void PooledMemoryAllocator::Deallocate(MemoryAllocation& allocation) {
        mPool.push_front(std::move(allocation));
    }

    uint64_t PooledMemoryAllocator::GetPoolSizeForTesting() const {
        return mPool.size();
    }
}  // namespace gpgmm
