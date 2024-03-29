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

#ifndef SRC_GPGMM_COMMON_INDEXEDMEMORYPOOL_H_
#define SRC_GPGMM_COMMON_INDEXEDMEMORYPOOL_H_

#include "gpgmm/common/MemoryPool.h"

#include <vector>

namespace gpgmm {

    // Stores direct mapped memory allocations.
    class IndexedMemoryPool final : public MemoryPoolBase {
        using UnderlyingContainerType = std::vector<std::unique_ptr<MemoryAllocationBase>>;
        using UnderlyingContainerIterator = UnderlyingContainerType::iterator;

      public:
        explicit IndexedMemoryPool(uint64_t memorySize);
        ~IndexedMemoryPool() override;

        // MemoryPoolBase interface
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> AcquireFromPool(
            uint64_t indexInPool) override;
        MaybeError ReturnToPool(std::unique_ptr<MemoryAllocationBase> allocation,
                                uint64_t indexInPool) override;
        uint64_t ReleasePool(uint64_t bytesToRelease) override;
        uint64_t GetPoolSize() const override;
        void ShrinkPool(uint64_t lastIndex) override;

        UnderlyingContainerIterator begin();
        UnderlyingContainerIterator end();

      private:
        UnderlyingContainerType mVec;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_INDEXEDMEMORYPOOL_H_
