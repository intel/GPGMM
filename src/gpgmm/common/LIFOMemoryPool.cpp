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

#include "gpgmm/common/MemoryAllocation.h"
#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Assert.h"

namespace gpgmm {

    LIFOMemoryPool::LIFOMemoryPool(uint64_t memorySize) : MemoryPoolBase(memorySize) {
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> LIFOMemoryPool::AcquireFromPool(
        uint64_t indexInPool) {
        GPGMM_RETURN_ERROR_IF(this, indexInPool != kInvalidIndex,
                              "Index was specified but not allowed", ErrorCode::kBadOperation);

        std::unique_ptr<MemoryAllocationBase> allocation;
        if (!mPool.empty()) {
            allocation = std::move(mPool.front());
            mPool.pop_front();
        }

        return allocation;
    }

    MaybeError LIFOMemoryPool::ReturnToPool(std::unique_ptr<MemoryAllocationBase> allocation,
                                            uint64_t indexInPool) {
        GPGMM_RETURN_ERROR_IF(this, indexInPool != kInvalidIndex,
                              "Index was specified but not allowed", ErrorCode::kBadOperation);
        mPool.push_front(std::move(allocation));
        return {};
    }

    uint64_t LIFOMemoryPool::ReleasePool(uint64_t bytesToRelease) {
        return TrimPoolUntil(mPool, bytesToRelease);
    }

    uint64_t LIFOMemoryPool::GetPoolSize() const {
        return mPool.size();
    }
}  // namespace gpgmm
