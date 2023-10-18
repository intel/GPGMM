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

#include "gpgmm/common/LIFOMemoryPool.h"

namespace gpgmm {

    LIFOMemoryPool::LIFOMemoryPool(uint64_t memorySize) : MemoryPoolBase(memorySize) {
    }

    LIFOMemoryPool::~LIFOMemoryPool() {
        ReleasePool(kInvalidSize);
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> LIFOMemoryPool::AcquireFromPool(
        uint64_t indexInPool) {
        GPGMM_RETURN_ERROR_IF(this, indexInPool != kInvalidIndex,
                              "Index was specified but not allowed", ErrorCode::kBadOperation);

        std::unique_ptr<MemoryAllocationBase> allocation;
        if (!mStack.empty()) {
            allocation = std::move(mStack.front());
            mStack.pop_front();
        }

        return allocation;
    }

    MaybeError LIFOMemoryPool::ReturnToPool(std::unique_ptr<MemoryAllocationBase> allocation,
                                            uint64_t indexInPool) {
        GPGMM_RETURN_ERROR_IF(this, indexInPool != kInvalidIndex,
                              "Index was specified but not allowed", ErrorCode::kBadOperation);
        mStack.push_front(std::move(allocation));
        return {};
    }

    uint64_t LIFOMemoryPool::ReleasePool(uint64_t bytesToRelease) {
        return DeallocateMemoryAndShrinkUntil(this, bytesToRelease);
    }

    uint64_t LIFOMemoryPool::GetPoolSize() const {
        return mStack.size();
    }

    LIFOMemoryPool::UnderlyingContainerIterator LIFOMemoryPool::begin() {
        return mStack.begin();
    }

    LIFOMemoryPool::UnderlyingContainerIterator LIFOMemoryPool::end() {
        return mStack.end();
    }

    void LIFOMemoryPool::ShrinkPool(uint64_t lastIndex) {
        mStack.erase(begin(), begin() + lastIndex);
    }

}  // namespace gpgmm
