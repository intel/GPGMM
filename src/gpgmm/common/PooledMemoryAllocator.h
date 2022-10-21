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

#ifndef GPGMM_COMMON_POOLEDMEMORYALLOCATOR_H_
#define GPGMM_COMMON_POOLEDMEMORYALLOCATOR_H_

#include "gpgmm/common/MemoryAllocator.h"

namespace gpgmm {

    class MemoryPoolBase;

    // |PooledMemoryAllocator| allocates memory of fixed size and same alignment using a pool.
    class PooledMemoryAllocator final : public MemoryAllocator {
      public:
        PooledMemoryAllocator(uint64_t memorySize,
                              uint64_t memoryAlignment,
                              std::unique_ptr<MemoryAllocator> memoryAllocator);
        ~PooledMemoryAllocator() override;

        // MemoryAllocator interface
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;
        uint64_t ReleaseMemory(uint64_t bytesToRelease = kInvalidSize) override;
        uint64_t GetMemorySize() const override;
        uint64_t GetMemoryAlignment() const override;

      private:
        const char* GetTypename() const override;

        std::unique_ptr<MemoryPoolBase> mPool;
        uint64_t mMemoryAlignment;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_POOLEDMEMORYALLOCATOR_H_
