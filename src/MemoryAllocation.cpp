// Copyright 2019 The Dawn Authors
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

#include "src/MemoryAllocation.h"
#include "src/Memory.h"
#include "src/common/Assert.h"
#include "src/common/IntegerTypes.h"

namespace gpgmm {

    MemoryAllocation::MemoryAllocation()
        : mAllocator(nullptr), mOffset(kInvalidOffset), mMemory(nullptr), mMappedPointer(nullptr) {
    }

    MemoryAllocation::MemoryAllocation(AllocatorBase* allocator,
                                       const AllocationInfo& info,
                                       uint64_t offset,
                                       MemoryBase* memory,
                                       uint8_t* mappedPointer)
        : mAllocator(allocator),
          mInfo(info),
          mOffset(offset),
          mMemory(memory),
          mMappedPointer(mappedPointer) {
    }

    bool MemoryAllocation::operator==(const MemoryAllocation& other) {
        return (other.mAllocator == mAllocator && other.mOffset == mOffset &&
                other.mMemory == mMemory);
    }

    MemoryBase* MemoryAllocation::GetMemory() const {
        return mMemory;
    }

    uint64_t MemoryAllocation::GetOffset() const {
        ASSERT(mOffset != kInvalidOffset);
        return mOffset;
    }

    AllocationInfo MemoryAllocation::GetInfo() const {
        return mInfo;
    }

    uint8_t* MemoryAllocation::GetMappedPointer() const {
        return mMappedPointer;
    }

    void MemoryAllocation::Reset() {
        mMemory = nullptr;
        mInfo = {};
        mOffset = kInvalidOffset;
    }

    AllocatorBase* MemoryAllocation::GetAllocator() {
        return mAllocator;
    }
}  // namespace gpgmm
