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

#ifndef GPGMM_VIRTUALBUDDYALLOCATOR_H_
#define GPGMM_VIRTUALBUDDYALLOCATOR_H_

#include "src/BuddyAllocator.h"
#include "src/MemoryAllocator.h"

#include <memory>
#include <vector>

namespace gpgmm {

    // VirtualBuddyAllocator uses the buddy allocator to sub-allocate blocks of device
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
    class VirtualBuddyAllocator : public MemoryAllocator {
      public:
        VirtualBuddyAllocator(uint64_t maxSystemSize, MemoryAllocator* memoryAllocator);
        ~VirtualBuddyAllocator() override;

        // MemoryAllocator interface
        MemoryAllocation SubAllocateMemory(uint64_t size, uint64_t alignment) override;
        void AllocateMemory(MemoryAllocation** ppAllocation) override;
        void DeallocateMemory(MemoryAllocation* pAllocation) override;
        void ReleaseMemory() override;

        uint64_t GetMemorySize() const override;
        uint64_t GetMemoryAlignment() const override;
        uint64_t GetPoolSizeForTesting() const override;

      private:
        uint64_t GetMemoryIndex(uint64_t offset) const;

        MemoryAllocator* mMemoryAllocator;

        uint64_t mMemorySize = 0;

        BuddyAllocator mBuddyBlockAllocator;

        std::vector<std::unique_ptr<MemoryAllocation>> mMemoryAllocations;
    };

}  // namespace gpgmm

#endif  // GPGMM_VIRTUALBUDDYALLOCATOR_H_
