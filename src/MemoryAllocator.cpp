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

#include "src/MemoryAllocator.h"
#include "common/Assert.h"

namespace gpgmm {

    MemoryAllocation MemoryAllocator::SubAllocateMemory(uint64_t size, uint64_t alignment) {
        return GPGMM_INVALID_ALLOCATION;
    }

    void MemoryAllocator::ReleaseMemory() {
    }

    uint64_t MemoryAllocator::GetMemorySize() const {
        ASSERT(false);
        return kInvalidSize;
    }

    uint64_t MemoryAllocator::GetMemoryAlignment() const {
        ASSERT(false);
        return kInvalidOffset;
    }

    uint64_t MemoryAllocator::GetPoolSizeForTesting() const {
        return 0;
    }

    bool MemoryAllocator::IsSubAllocated(const MemoryAllocation& allocation) const {
        return allocation.IsSubAllocated();
    }

    void MemoryAllocator::IncrementSubAllocatedRef(MemoryAllocation* pAllocation) {
        pAllocation->IncrementSubAllocatedRef();
    }

    void MemoryAllocator::DecrementSubAllocatedRef(MemoryAllocation* pAllocation) {
        pAllocation->DecrementSubAllocatedRef();
    }
}  // namespace gpgmm
