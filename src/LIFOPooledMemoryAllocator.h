// Copyright 2020 The Dawn Authors
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

#ifndef GPGMM_LIFOPOOLEDMEMORYALLOCATOR_H_
#define GPGMM_LIFOPOOLEDMEMORYALLOCATOR_H_

#include "src/LIFOMemoryPool.h"
#include "src/MemoryAllocator.h"

namespace gpgmm {

    // |LIFOPooledMemoryAllocator| allocates from a memory pool using the LIFO strategy.
    class LIFOPooledMemoryAllocator : public MemoryAllocator {
      public:
        LIFOPooledMemoryAllocator(MemoryAllocator* memoryAllocator);
        ~LIFOPooledMemoryAllocator() override;

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> AllocateMemory(uint64_t size,
                                                         uint64_t alignment,
                                                         bool neverAllocate) override;
        void DeallocateMemory(MemoryAllocation* allocation) override;
        void ReleaseMemory() override;

        uint64_t GetMemorySize() const override;
        uint64_t GetMemoryAlignment() const override;
        uint64_t GetPoolSizeForTesting() const override;

      private:
        MemoryAllocator* mMemoryAllocator = nullptr;

        LIFOMemoryPool mMemoryPool;
    };

}  // namespace gpgmm

#endif  // GPGMM_LIFOPOOLEDMEMORYALLOCATOR_H_
