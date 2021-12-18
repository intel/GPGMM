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

#ifndef GPGMM_COMBINED_MEMORY_ALLOCATOR_H_
#define GPGMM_COMBINED_MEMORY_ALLOCATOR_H_

#include "src/MemoryAllocator.h"

#include <vector>

namespace gpgmm {

    // Combines multiple memory allocators together.
    class CombinedMemoryAllocator : public MemoryAllocator {
      public:
        CombinedMemoryAllocator() = default;
        ~CombinedMemoryAllocator() override = default;

        MemoryAllocator* PushAllocator(std::unique_ptr<MemoryAllocator> allocator);

        // MemoryAllocator interface.
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t size,
                                                            uint64_t alignment,
                                                            bool neverAllocate) override;
        void DeallocateMemory(MemoryAllocation* allocation) override;
        void ReleaseMemory() override;

        MEMORY_ALLOCATOR_INFO QueryInfo() const override;

      private:
        std::vector<std::unique_ptr<MemoryAllocator>> mAllocators;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMBINED_MEMORY_ALLOCATOR_H_
