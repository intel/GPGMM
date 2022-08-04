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

#include "gpgmm/common/IndexedMemoryPool.h"

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/TraceEvent.h"

namespace gpgmm {

    IndexedMemoryPool::IndexedMemoryPool(uint64_t memorySize) : MemoryPool(memorySize) {
    }

    MemoryAllocation IndexedMemoryPool::AcquireFromPool(uint64_t indexInPool) {
        if (indexInPool >= mPool.size()) {
            mPool.resize(indexInPool + 1);
        }
        MemoryAllocation tmp = mPool[indexInPool];
        mPool[indexInPool] = {};  // invalidate it
        return tmp;
    }

    void IndexedMemoryPool::ReturnToPool(MemoryAllocation allocation, uint64_t indexInPool) {
        ASSERT(indexInPool < mPool.size());
        ASSERT(allocation.GetSize() == GetMemorySize());
        mPool[indexInPool] = std::move(allocation);
    }

    uint64_t IndexedMemoryPool::ReleasePool(uint64_t bytesToRelease) {
        return TrimPoolUntil(mPool, bytesToRelease);
    }

    uint64_t IndexedMemoryPool::GetPoolSize() const {
        uint64_t count = 0;
        for (auto& allocation : mPool) {
            if (allocation != GPGMM_ERROR_INVALID_ALLOCATION) {
                count++;
            }
        }
        return count;
    }
}  // namespace gpgmm
