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

#ifndef GPGMM_COMMON_DEDICATEDMEMORYALLOCATOR_H_
#define GPGMM_COMMON_DEDICATEDMEMORYALLOCATOR_H_

#include "gpgmm/common/MemoryAllocator.h"

namespace gpgmm {

    // DedicatedMemoryAllocator allocates from device memory with exactly one block.
    // DedicatedMemoryAllocator is useful in situations where whole memory objects could be reused
    // without the need for sub-allocation. DedicatedMemoryAllocator also allows
    // memory to be tracked.
    class DedicatedMemoryAllocator final : public MemoryAllocatorBase {
      public:
        DedicatedMemoryAllocator(std::unique_ptr<MemoryAllocatorBase> memoryAllocator,
                                 uint64_t memoryAlignment);

        // MemoryAllocatorBase interface
        ResultOrError<std::unique_ptr<MemoryAllocation>> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> subAllocation) override;
        uint64_t GetMemoryAlignment() const override;

        MemoryAllocatorStats GetStats() const override;

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(DedicatedMemoryAllocator)

        const uint64_t mMemoryAlignment;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_DEDICATEDMEMORYALLOCATOR_H_
