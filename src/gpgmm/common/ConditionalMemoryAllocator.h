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

#ifndef SRC_GPGMM_COMMON_CONDITIONALMEMORYALLOCATOR_H_
#define SRC_GPGMM_COMMON_CONDITIONALMEMORYALLOCATOR_H_

#include "gpgmm/common/MemoryAllocator.h"

namespace gpgmm {

    // Conditionally allocates depending on the size.
    // If the allocation size is less then or equal to the |conditionalSize|, the |firstAllocator|
    // will be used, else |secondAllocator|.
    class ConditionalMemoryAllocator final : public MemoryAllocatorBase {
      public:
        ConditionalMemoryAllocator(std::unique_ptr<MemoryAllocatorBase> firstAllocator,
                                   std::unique_ptr<MemoryAllocatorBase> secondAllocator,
                                   uint64_t conditionalSize);
        ~ConditionalMemoryAllocator() override = default;

        // MemoryAllocatorBase interface
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) override;

        MemoryAllocatorStats GetStats() const override;

        MemoryAllocatorBase* GetFirstAllocatorForTesting() const;
        MemoryAllocatorBase* GetSecondAllocatorForTesting() const;

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(ConditionalMemoryAllocator)

        std::unique_ptr<MemoryAllocatorBase> mFirstAllocator;
        std::unique_ptr<MemoryAllocatorBase> mSecondAllocator;

        uint64_t mConditionalSize;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_CONDITIONALMEMORYALLOCATOR_H_
