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

#ifndef SRC_GPGMM_COMMON_DEDICATEDMEMORYALLOCATOR_H_
#define SRC_GPGMM_COMMON_DEDICATEDMEMORYALLOCATOR_H_

#include "gpgmm/common/MemoryAllocator.h"

namespace gpgmm {

    // DedicatedMemoryAllocator always allocates the entire region of memory.
    // This is useful in situations where entire memory allocations could be reused
    // without the need for sub-allocation.
    class DedicatedMemoryAllocator final : public MemoryAllocatorBase {
      public:
        // Constructs a dedicated allocation.
        // The underlying |memoryAllocator| cannot be a sub-allocator.
        DedicatedMemoryAllocator(ScopedRef<MemoryAllocatorBase> memoryAllocator,
                                 uint64_t memoryAlignment);

        // MemoryAllocatorBase interface
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> subAllocation) override;
        uint64_t GetMemoryAlignment() const override;

        MemoryAllocatorStats GetStats() const override;

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(DedicatedMemoryAllocator)

        const uint64_t mMemoryAlignment;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_DEDICATEDMEMORYALLOCATOR_H_
