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

#include "gpgmm.h"

namespace gpgmm {

    // MemoryBase

    MemoryBase::MemoryBase(uint64_t size, uint64_t alignment) : mSize(size), mAlignment(alignment) {
    }

    uint64_t MemoryBase::GetSize() const {
        return mSize;
    }

    uint64_t MemoryBase::GetAlignment() const {
        return mAlignment;
    }

    // MemoryAllocator

    uint64_t MemoryAllocator::ReleaseMemory(uint64_t bytesToRelease) {
        return 0;
    }

    // MemoryAllocation

    MemoryAllocation::MemoryAllocation(MemoryAllocator* allocator, MemoryBase* memory)
        : mAllocator(allocator), mMemory(memory) {
    }

    MemoryBase* MemoryAllocation::GetMemory() const {
        return mMemory;
    }

    MemoryAllocator* MemoryAllocation::GetAllocator() const {
        return mAllocator;
    }

    uint64_t MemoryAllocation::GetSize() const {
        return mMemory->GetSize();
    }

    uint64_t MemoryAllocation::GetAlignment() const {
        return mMemory->GetAlignment();
    }

}  // namespace gpgmm
