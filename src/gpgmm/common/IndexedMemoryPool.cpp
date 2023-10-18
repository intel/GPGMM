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

namespace gpgmm {

    IndexedMemoryPool::IndexedMemoryPool(uint64_t memorySize) : MemoryPoolBase(memorySize) {
    }

    IndexedMemoryPool::~IndexedMemoryPool() {
        ReleasePool(kInvalidSize);
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> IndexedMemoryPool::AcquireFromPool(
        uint64_t indexInPool) {
        if (indexInPool >= mVec.size()) {
            mVec.resize(indexInPool + 1);
        }
        return std::unique_ptr<MemoryAllocationBase>(mVec[indexInPool].release());
    }

    MaybeError IndexedMemoryPool::ReturnToPool(std::unique_ptr<MemoryAllocationBase> allocation,
                                               uint64_t indexInPool) {
        GPGMM_RETURN_ERROR_IF(this, indexInPool >= mVec.size(), "Index exceeded pool size",
                              ErrorCode::kBadOperation);
        mVec[indexInPool] = std::move(allocation);
        return {};
    }

    uint64_t IndexedMemoryPool::ReleasePool(uint64_t bytesToRelease) {
        return DeallocateMemoryAndShrinkUntil(this, bytesToRelease);
    }

    uint64_t IndexedMemoryPool::GetPoolSize() const {
        uint64_t count = 0;
        for (auto& allocation : mVec) {
            if (allocation != nullptr) {
                count++;
            }
        }
        return count;
    }

    IndexedMemoryPool::UnderlyingContainerIterator IndexedMemoryPool::begin() {
        return mVec.begin();
    }

    IndexedMemoryPool::UnderlyingContainerIterator IndexedMemoryPool::end() {
        return mVec.end();
    }

    void IndexedMemoryPool::ShrinkPool(uint64_t lastIndex) {
        mVec.erase(begin(), begin() + lastIndex);
    }

}  // namespace gpgmm
