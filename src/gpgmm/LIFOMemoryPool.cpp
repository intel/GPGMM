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

#include "gpgmm/LIFOMemoryPool.h"

#include "gpgmm/MemoryAllocation.h"
#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/Serializer.h"
#include "gpgmm/common/Assert.h"

namespace gpgmm {

    LIFOMemoryPool::LIFOMemoryPool(uint64_t memorySize) : MemoryPool(memorySize) {
    }

    std::unique_ptr<MemoryAllocation> LIFOMemoryPool::AcquireFromPool(uint64_t memoryIndex) {
        ASSERT(memoryIndex == kInvalidIndex);

        std::unique_ptr<MemoryAllocation> allocation;
        if (!mPool.empty()) {
            allocation = std::move(mPool.front());
            mPool.pop_front();
        }

        RecordObject("GPUMemoryPool", this, GetInfo());

        return allocation;
    }

    void LIFOMemoryPool::ReturnToPool(std::unique_ptr<MemoryAllocation> allocation,
                                      uint64_t memoryIndex) {
        ASSERT(memoryIndex == kInvalidIndex);
        ASSERT(allocation != nullptr);

        mPool.push_front(std::move(allocation));

        RecordObject("GPUMemoryPool", this, GetInfo());
    }

    void LIFOMemoryPool::ReleasePool() {
        for (auto& allocation : mPool) {
            ASSERT(allocation != nullptr);
            allocation->GetAllocator()->DeallocateMemory(allocation.release());
        }

        mPool.clear();
    }

    uint64_t LIFOMemoryPool::GetPoolSize() const {
        return mPool.size();
    }
}  // namespace gpgmm
