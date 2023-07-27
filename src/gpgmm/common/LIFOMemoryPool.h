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

    // Pool using LIFO (newest are recycled first).
    class LIFOMemoryPool : public MemoryPoolBase {
      public:
        explicit LIFOMemoryPool(uint64_t memorySize);
        ~LIFOMemoryPool() override = default;

        // MemoryPoolBase interface
        MemoryAllocationBase AcquireFromPool(uint64_t indexInPool = kInvalidIndex) override;
        void ReturnToPool(MemoryAllocationBase allocation,
                          uint64_t indexInPool = kInvalidIndex) override;
        uint64_t ReleasePool(uint64_t bytesToFree = kInvalidSize) override;

        uint64_t GetPoolSize() const override;

      private:
        std::deque<MemoryAllocationBase> mPool;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_LIFOMEMORYPOOL_H_
