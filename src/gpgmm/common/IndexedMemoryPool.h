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

#ifndef GPGMM_COMMON_INDEXEDMEMORYPOOL_H_
#define GPGMM_COMMON_INDEXEDMEMORYPOOL_H_

#include "gpgmm/common/MemoryPool.h"

#include <vector>

namespace gpgmm {

    class IndexedMemoryPool final : public MemoryPool {
      public:
        explicit IndexedMemoryPool(uint64_t memorySize);
        ~IndexedMemoryPool() override = default;

        // MemoryPool interface
        MemoryAllocation AcquireFromPool(uint64_t indexInPool) override;
        void ReturnToPool(MemoryAllocation allocation, uint64_t indexInPool) override;
        uint64_t ReleasePool(uint64_t bytesToRelease) override;

        uint64_t GetPoolSize() const override;

      private:
        std::vector<MemoryAllocation> mPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_INDEXEDMEMORYPOOL_H_
