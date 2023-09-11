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

#include "gpgmm/common/IndexedMemoryPool.h"

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/TraceEvent.h"

namespace gpgmm {

    IndexedMemoryPool::IndexedMemoryPool(uint64_t memorySize) : MemoryPoolBase(memorySize) {
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> IndexedMemoryPool::AcquireFromPool(
        uint64_t indexInPool) {
        if (indexInPool >= mPool.size()) {
            mPool.resize(indexInPool + 1);
        }
        return std::unique_ptr<MemoryAllocationBase>(mPool[indexInPool].release());
    }

    MaybeError IndexedMemoryPool::ReturnToPool(std::unique_ptr<MemoryAllocationBase> allocation,
                                               uint64_t indexInPool) {
        GPGMM_RETURN_ERROR_IF(this, indexInPool >= mPool.size(), "Index exceeded pool size",
                              ErrorCode::kBadOperation);
        mPool[indexInPool] = std::move(allocation);
        return {};
    }

    uint64_t IndexedMemoryPool::ReleasePool(uint64_t bytesToRelease) {
        return TrimPoolUntil(this, bytesToRelease);
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

    IndexedMemoryPool::UnderlyingContainerType::iterator IndexedMemoryPool::begin() {
        return mPool.begin();
    }

    IndexedMemoryPool::UnderlyingContainerType::iterator IndexedMemoryPool::end() {
        return mPool.end();
    }

    void IndexedMemoryPool::ShrinkPool(uint64_t lastIndex) {
        mPool.erase(begin(), begin() + lastIndex);
    }

}  // namespace gpgmm
