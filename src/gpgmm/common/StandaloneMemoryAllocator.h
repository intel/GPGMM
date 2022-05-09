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

#ifndef GPGMM_COMMON_STANDALONEMEMORYALLOCATOR_H_
#define GPGMM_COMMON_STANDALONEMEMORYALLOCATOR_H_

#include "gpgmm/common/MemoryAllocator.h"

#include <memory>

namespace gpgmm {

    // StandaloneMemoryAllocator sub-allocates memory with exactly one block.
    class StandaloneMemoryAllocator final : public MemoryAllocator {
      public:
        StandaloneMemoryAllocator(std::unique_ptr<MemoryAllocator> memoryAllocator);

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(
            const MEMORY_ALLOCATION_REQUEST& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> subAllocation) override;

        MEMORY_ALLOCATOR_INFO GetInfo() const override;
        const char* GetTypename() const override;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_STANDALONEMEMORYALLOCATOR_H_
