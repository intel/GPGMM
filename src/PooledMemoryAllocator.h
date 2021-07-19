// Copyright 2020 The Dawn Authors
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

#include "src/ResourceMemoryAllocator.h"

#include <deque>

namespace gpgmm {

    // |PooledMemoryAllocator| allocates a fixed-size resource memory from a resource memory
    // pool. Internally, it manages a list of heaps using LIFO (newest heaps are recycled first).
    // The heap is in one of two states: AVAILABLE or not. Upon de-allocate, the heap is returned
    // the pool and made AVAILABLE.
    class PooledMemoryAllocator : public ResourceMemoryAllocator {
      public:
        PooledMemoryAllocator(ResourceMemoryAllocator* heapAllocator);
        ~PooledMemoryAllocator() override = default;

        ResourceMemoryAllocation Allocate(uint64_t size) override;
        void Deallocate(ResourceMemoryAllocation& allocation) override;
        void Release() override;

        // For testing purposes.
        uint64_t GetPoolSizeForTesting() const;

      private:
        ResourceMemoryAllocator* mHeapAllocator = nullptr;

        std::deque<ResourceMemoryAllocation> mPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_POOLEDMEMORYALLOCATOR_H_
