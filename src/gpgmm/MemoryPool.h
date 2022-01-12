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

#include "gpgmm/common/Limits.h"

#include <memory>

namespace gpgmm {

    class MemoryAllocation;

    struct POOL_DESC {
        size_t UnusedPoolSize;
    };

    // Stores a collection of fixed-size memory blocks.
    class MemoryPool {
      public:
        MemoryPool();
        virtual ~MemoryPool();

        // Retrieves a memory allocation from the pool using an optional index.
        virtual std::unique_ptr<MemoryAllocation> AcquireFromPool(
            uint64_t memoryIndex = kInvalidIndex) = 0;

        // Returns a memory allocation back to the pool using an optional index.
        virtual void ReturnToPool(std::unique_ptr<MemoryAllocation> allocation,
                                  uint64_t memoryIndex = kInvalidIndex) = 0;

        // Deallocates memory allocations owned by the pool.
        virtual void ReleasePool() = 0;

        // Returns number of memory allocations in the pool.
        virtual uint64_t GetPoolSize() const = 0;

        POOL_DESC GetDesc() const;
    };

}  // namespace gpgmm

#endif  // GPGMM_MEMORYPOOL_H_
