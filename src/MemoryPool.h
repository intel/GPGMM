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

#ifndef GPGMM_MEMORYPOOL_H_
#define GPGMM_MEMORYPOOL_H_

#include <memory>

namespace gpgmm {

    class MemoryAllocation;

    // Stores a set of fixe-sized memory blocks or heaps in memory.
    class MemoryPool {
      public:
        virtual ~MemoryPool() = default;

        virtual std::unique_ptr<MemoryAllocation> AcquireFromPool() = 0;
        virtual void ReturnToPool(std::unique_ptr<MemoryAllocation> allocation) = 0;
        virtual void ReleasePool() = 0;

        virtual uint64_t GetPoolSize() const = 0;
    };

}  // namespace gpgmm

#endif  // GPGMM_MEMORYPOOL_H_
