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

#ifndef GPGMM_POOLEDMEMORYALLOCATOR_H_
#define GPGMM_POOLEDMEMORYALLOCATOR_H_

#include "src/MemoryAllocator.h"

namespace gpgmm {

    class MemoryPool;

    // |PooledMemoryAllocator| allocates memory of fixed size and same alignment using a pool.
    class PooledMemoryAllocator : public MemoryAllocator {
      public:
        PooledMemoryAllocator(MemoryAllocator* memoryAllocator, MemoryPool* memoryPool);
        ~PooledMemoryAllocator() override = default;

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> AllocateMemory(uint64_t size,
                                                         uint64_t alignment,
                                                         bool neverAllocate) override;
        void DeallocateMemory(MemoryAllocation* allocation) override;

      private:
        MemoryAllocator* const mMemoryAllocator;
        MemoryPool* const mMemoryPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_POOLEDMEMORYALLOCATOR_H_
