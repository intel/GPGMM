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

#include "gpgmm/IndexedMemoryPool.h"

#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/Serializer.h"

namespace gpgmm {

    IndexedMemoryPool::IndexedMemoryPool(uint64_t memorySize) : MemoryPool(memorySize) {
    }

    std::unique_ptr<MemoryAllocation> IndexedMemoryPool::AcquireFromPool(uint64_t memoryIndex) {
        if (memoryIndex >= mPool.size()) {
            mPool.resize(memoryIndex + 1);
        }

        std::unique_ptr<MemoryAllocation> allocation = std::move(mPool[memoryIndex]);
        RecordEvent("GPUMemoryPool", this, GetInfo());

        return allocation;
    }

    void IndexedMemoryPool::ReturnToPool(std::unique_ptr<MemoryAllocation> allocation,
                                         uint64_t memoryIndex) {
        ASSERT(allocation != nullptr);
        ASSERT(memoryIndex < mPool.size());

        mPool[memoryIndex] = std::move(allocation);

        RecordEvent("GPUMemoryPool", this, GetInfo());
    }

    void IndexedMemoryPool::ReleasePool() {
        for (auto& allocation : mPool) {
            if (allocation != nullptr) {
                allocation->GetAllocator()->DeallocateMemory(allocation.release());
            }
        }

        mPool.clear();
    }

    uint64_t IndexedMemoryPool::GetPoolSize() const {
        uint64_t count = 0;
        for (auto& allocation : mPool) {
            if (allocation != nullptr) {
                count++;
            }
        }
        return count;
    }
}  // namespace gpgmm
