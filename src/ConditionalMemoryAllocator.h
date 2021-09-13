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

    // Conditionally sub-allocates memory depending on the requested allocation size.
    // If the allocation size is less then the |conditionalSize|, the |firstAllocator| will be used.
    class ConditionalMemoryAllocator : public MemoryAllocator {
      public:
        ConditionalMemoryAllocator(MemoryAllocator* firstAllocator,
                                   MemoryAllocator* secondAllocator,
                                   uint64_t conditionalSize);
        ~ConditionalMemoryAllocator() override = default;

        // MemoryAllocator interface
        MemoryAllocation SubAllocateMemory(uint64_t size, uint64_t alignment) override;
        void AllocateMemory(MemoryAllocation** ppAllocation) override;
        void DeallocateMemory(MemoryAllocation* pAllocation) override;
        void ReleaseMemory() override;

        uint64_t GetMemorySize() const override;
        uint64_t GetMemoryAlignment() const override;

      private:
        MemoryAllocator* mFirstAllocator = nullptr;
        MemoryAllocator* mSecondAllocator = nullptr;

        uint64_t mConditionalSize;
    };

}  // namespace gpgmm

#endif  // GPGMM_CONDITIONALMEMORYALLOCATOR_H_