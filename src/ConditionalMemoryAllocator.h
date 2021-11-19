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

#ifndef GPGMM_CONDITIONALMEMORYALLOCATOR_H_
#define GPGMM_CONDITIONALMEMORYALLOCATOR_H_

#include "src/MemoryAllocator.h"

namespace gpgmm {

    // Conditionally allocates depending on the size.
    // If the allocation size is less then or equal to the |conditionalSize|, the |firstAllocator|
    // will be used.
    class ConditionalMemoryAllocator : public MemoryAllocator {
      public:
        ConditionalMemoryAllocator(MemoryAllocator* firstAllocator,
                                   MemoryAllocator* secondAllocator,
                                   uint64_t conditionalSize);
        ~ConditionalMemoryAllocator() override = default;

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> AllocateMemory(uint64_t size,
                                                         uint64_t alignment,
                                                         bool neverAllocate = true) override;
        void DeallocateMemory(MemoryAllocation* pAllocation) override;

      private:
        MemoryAllocator* mFirstAllocator = nullptr;
        MemoryAllocator* mSecondAllocator = nullptr;

        uint64_t mConditionalSize;
    };

}  // namespace gpgmm

#endif  // GPGMM_CONDITIONALMEMORYALLOCATOR_H_
