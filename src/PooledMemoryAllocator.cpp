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

#include "src/PooledMemoryAllocator.h"
#include "common/Assert.h"

namespace gpgmm {

    PooledMemoryAllocator::PooledMemoryAllocator(MemoryAllocator* memoryAllocator,
                                                 MemoryPool* memoryPool)
        : mMemoryAllocator(memoryAllocator), mMemoryPool(memoryPool) {
        ASSERT(mMemoryPool != nullptr);
        ASSERT(mMemoryAllocator != nullptr);
    }

    PooledMemoryAllocator::~PooledMemoryAllocator() {
        ASSERT(mMemoryPool->GetPoolSize() == 0);
    }

    std::unique_ptr<MemoryAllocation> PooledMemoryAllocator::AllocateMemory(uint64_t size,
                                                                            uint64_t alignment,
                                                                            bool neverAllocate) {
        if (GetMemorySize() != size || GetMemoryAlignment() != alignment) {
            return {};
        }
        std::unique_ptr<MemoryAllocation> allocation = mMemoryPool->AcquireFromPool();
        if (allocation == nullptr) {
            allocation = mMemoryAllocator->AllocateMemory(GetMemorySize(), GetMemoryAlignment(),
                                                          neverAllocate);
        }

        return allocation;
    }

    void PooledMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        mMemoryPool->ReturnToPool(std::unique_ptr<MemoryAllocation>(allocation));
    }

    uint64_t PooledMemoryAllocator::GetMemorySize() const {
        return mMemoryAllocator->GetMemorySize();
    }

    uint64_t PooledMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAllocator->GetMemoryAlignment();
    }
}  // namespace gpgmm
