// Copyright 2019 The Dawn Authors
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

#include "src/MemoryAllocation.h"
#include "common/Assert.h"
#include "common/IntegerTypes.h"
#include "src/Memory.h"

namespace gpgmm {

    MemoryAllocation::MemoryAllocation()
        : mAllocator(nullptr), mMemory(nullptr), mMappedPointer(nullptr) {
    }

    MemoryAllocation::MemoryAllocation(MemoryAllocator* allocator,
                                       const AllocationInfo& info,
                                       MemoryBase* memory,
                                       uint8_t* mappedPointer)
        : mAllocator(allocator), mInfo(info), mMemory(memory), mMappedPointer(mappedPointer) {
    }

    bool AllocationInfo::operator==(const AllocationInfo& other) const {
        return other.Block == Block && other.Offset == Offset && other.Method == Method;
    }

    bool MemoryAllocation::operator==(const MemoryAllocation& other) const {
        return (other.mAllocator == mAllocator && other.mMemory == mMemory && other.mInfo == mInfo);
    }

    bool MemoryAllocation::operator!=(const MemoryAllocation& other) const {
        return !operator==(other);
    }

    MemoryBase* MemoryAllocation::GetMemory() const {
        return mMemory;
    }

    AllocationInfo MemoryAllocation::GetInfo() const {
        return mInfo;
    }

    uint8_t* MemoryAllocation::GetMappedPointer() const {
        return mMappedPointer;
    }

    void MemoryAllocation::Reset() {
        mAllocator = nullptr;
        mInfo = {};
        mMemory = nullptr;
        mMappedPointer = nullptr;
    }

    MemoryAllocator* MemoryAllocation::GetAllocator() const {
        return mAllocator;
    }

}  // namespace gpgmm
