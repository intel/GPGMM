// Copyright 2019 The Dawn Authors
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

#ifndef GPGMM_BUDDYMEMORYALLOCATOR_H_
#define GPGMM_BUDDYMEMORYALLOCATOR_H_

#include "gpgmm/BuddyBlockAllocator.h"
#include "gpgmm/IndexedMemoryPool.h"
#include "gpgmm/MemoryAllocator.h"

#include <memory>

namespace gpgmm {

    // BuddyMemoryAllocator uses the buddy allocator to sub-allocate blocks of device
    // memory created by MemoryAllocator clients. It creates a very large buddy system
    // where backing device memory blocks equal a specified level in the system.
    //
    // Upon sub-allocating, the offset gets mapped to device memory by computing the corresponding
    // memory index and should the memory not exist, it is created. If two sub-allocations share the
    // same memory index, the memory refcount is incremented to ensure de-allocating one doesn't
    // release the other prematurely.
    //
    // The MemoryAllocator should return ResourceHeaps that are all compatible with each other.
    // It should also outlive all the resources that are in the buddy allocator.
    class BuddyMemoryAllocator : public MemoryAllocator {
      public:
        BuddyMemoryAllocator(uint64_t systemSize,
                             uint64_t memorySize,
                             uint64_t memoryAlignment,
                             std::unique_ptr<MemoryAllocator> memoryAllocator);

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t allocationSize,
                                                            uint64_t alignment,
                                                            bool neverAllocate,
                                                            bool cacheSize) override;
        void DeallocateMemory(MemoryAllocation* subAllocation) override;

        uint64_t GetMemorySize() const override;
        uint64_t GetMemoryAlignment() const override;
        MEMORY_ALLOCATOR_INFO QueryInfo() const override;

        uint64_t GetBuddyMemorySizeForTesting() const;

      private:
        uint64_t GetMemoryIndex(uint64_t offset) const;

        const uint64_t mMemorySize;
        const uint64_t mMemoryAlignment;

        BuddyBlockAllocator mBuddyBlockAllocator;

        IndexedMemoryPool mPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_BUDDYMEMORYALLOCATOR_H_
