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

#ifndef SRC_GPGMM_COMMON_LIFOMEMORYPOOL_H_
#define SRC_GPGMM_COMMON_LIFOMEMORYPOOL_H_

#include "gpgmm/common/MemoryPool.h"

#include <deque>

namespace gpgmm {

    // LIFO storage of memory allocations (newest are recycled first).
    class LIFOMemoryPool : public MemoryPoolBase {
        using UnderlyingContainerType = std::deque<std::unique_ptr<MemoryAllocationBase>>;
        using UnderlyingContainerIterator = UnderlyingContainerType::iterator;

      public:
        explicit LIFOMemoryPool(uint64_t memorySize);
        ~LIFOMemoryPool() override;

        // MemoryPoolBase interface
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> AcquireFromPool(
            uint64_t indexInPool = kInvalidIndex) override;
        MaybeError ReturnToPool(std::unique_ptr<MemoryAllocationBase> allocation,
                                uint64_t indexInPool = kInvalidIndex) override;
        uint64_t ReleasePool(uint64_t bytesToFree = kInvalidSize) override;
        uint64_t GetPoolSize() const override;
        void ShrinkPool(uint64_t lastIndex) override;

        UnderlyingContainerIterator begin();
        UnderlyingContainerIterator end();

      private:
        UnderlyingContainerType mStack;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_LIFOMEMORYPOOL_H_
