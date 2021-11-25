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

#ifndef GPGMM_LIFOMEMORYPOOL_H_
#define GPGMM_LIFOMEMORYPOOL_H_

#include "src/MemoryPool.h"

#include <deque>

namespace gpgmm {

    // Pools memory using LIFO queue (newest are recycled first).
    class LIFOMemoryPool : public MemoryPool {
      public:
        LIFOMemoryPool() = default;
        ~LIFOMemoryPool() override = default;

        // MemoryPool interface
        std::unique_ptr<MemoryAllocation> AcquireFromPool(
            uint64_t memoryIndex = kInvalidIndex) override;
        void ReturnToPool(std::unique_ptr<MemoryAllocation> allocation,
                          uint64_t memoryIndex = kInvalidIndex) override;
        void ReleasePool() override;

        uint64_t GetPoolSize() const override;

      private:
        std::deque<std::unique_ptr<MemoryAllocation>> mPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_LIFOMEMORYPOOL_H_
