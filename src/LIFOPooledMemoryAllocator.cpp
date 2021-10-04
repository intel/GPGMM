// Copyright 2020 The Dawn Authors
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

#include "src/LIFOPooledMemoryAllocator.h"
#include "common/Assert.h"

namespace gpgmm {

    LIFOPooledMemoryAllocator::LIFOPooledMemoryAllocator(MemoryAllocator* memoryAllocator)
        : mMemoryAllocator(memoryAllocator) {
    }

    LIFOPooledMemoryAllocator::~LIFOPooledMemoryAllocator() {
        ASSERT(GetPoolSizeForTesting() == 0);
    }

    void LIFOPooledMemoryAllocator::ReleaseMemory() {
        mMemoryPool.ReleasePool();
    }

    std::unique_ptr<MemoryAllocation> LIFOPooledMemoryAllocator::AllocateMemory(
        uint64_t size,
        uint64_t alignment) {
        // Pooled memory is LIFO because memory can be evicted by LRU. However, this means
        // pooling is disabled in-frame when the memory is still pending. For high in-frame
        // memory users, FIFO might be preferable when memory consumption is a higher priority.
        std::unique_ptr<MemoryAllocation> allocation = mMemoryPool.AcquireFromPool();
        if (allocation == nullptr) {
            allocation = mMemoryAllocator->AllocateMemory(size, alignment);
        }

        return allocation;
    }

    void LIFOPooledMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        mMemoryPool.ReturnToPool(std::unique_ptr<MemoryAllocation>(allocation));
    }

    uint64_t LIFOPooledMemoryAllocator::GetMemorySize() const {
        return mMemoryAllocator->GetMemorySize();
    }

    uint64_t LIFOPooledMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAllocator->GetMemoryAlignment();
    }

    uint64_t LIFOPooledMemoryAllocator::GetPoolSizeForTesting() const {
        return mMemoryPool.GetPoolSize();
    }
}  // namespace gpgmm
