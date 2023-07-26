// Copyright 2019 The Dawn Authors
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

#ifndef GPGMM_COMMON_BUDDYMEMORYALLOCATOR_H_
#define GPGMM_COMMON_BUDDYMEMORYALLOCATOR_H_

#include "gpgmm/common/BuddyBlockAllocator.h"
#include "gpgmm/common/IndexedMemoryPool.h"
#include "gpgmm/common/MemoryAllocator.h"

#include <memory>

namespace gpgmm {

    // BuddyMemoryAllocator uses the buddy allocator to sub-allocate blocks of device
    // memory created by MemoryAllocatorBase clients. It creates a very large buddy system
    // where backing device memory blocks equal a specified level in the system.
    //
    // Upon sub-allocating, the offset gets mapped to device memory by computing the corresponding
    // memory index and should the memory not exist, it is created. If two sub-allocations share the
    // same memory index, the memory refcount is incremented to ensure de-allocating one doesn't
    // release the other prematurely.
    //
    // The MemoryAllocatorBase should return ResourceHeaps that are all compatible with each other.
    // It should also outlive all the resources that are in the buddy allocator.
    class BuddyMemoryAllocator final : public MemoryAllocatorBase {
      public:
        BuddyMemoryAllocator(uint64_t systemSize,
                             uint64_t memorySize,
                             uint64_t memoryAlignment,
                             std::unique_ptr<MemoryAllocatorBase> memoryAllocator);

        // MemoryAllocatorBase interface
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> subAllocation) override;

        uint64_t GetMemorySize() const override;
        uint64_t GetMemoryAlignment() const override;
        MemoryAllocatorStats GetStats() const override;

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(BuddyMemoryAllocator)

        uint64_t GetMemoryIndex(uint64_t offset) const;

        const uint64_t mMemorySize;
        const uint64_t mMemoryAlignment;

        BuddyBlockAllocator mBuddyBlockAllocator;

        // Set of fixed memory allocations containing at-least one sub-allocation.
        IndexedMemoryPool mUsedPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_BUDDYMEMORYALLOCATOR_H_
