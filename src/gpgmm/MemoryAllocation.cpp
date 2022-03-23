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

#include "gpgmm/MemoryAllocation.h"
#include "gpgmm/BlockAllocator.h"
#include "gpgmm/Memory.h"
#include "gpgmm/common/Assert.h"
#include "gpgmm/common/Limits.h"

namespace gpgmm {

    MemoryAllocation::MemoryAllocation()
        : mAllocator(nullptr),
          mMemory(nullptr),
          mOffset(kInvalidOffset),
          mMethod(AllocationMethod::kUndefined),
          mBlock(nullptr),
          mMappedPointer(nullptr) {
    }

    MemoryAllocation::MemoryAllocation(MemoryAllocator* allocator,
                                       MemoryBase* memory,
                                       uint64_t offset,
                                       AllocationMethod method,
                                       Block* block,
                                       uint8_t* mappedPointer)
        : mAllocator(allocator),
          mMemory(memory),
          mOffset(offset),
          mMethod(method),
          mBlock(block),
          mMappedPointer(mappedPointer) {
    }

    MemoryAllocation::MemoryAllocation(MemoryAllocator* allocator,
                                       MemoryBase* memory,
                                       uint8_t* mappedPointer)
        : mAllocator(allocator),
          mMemory(memory),
          mOffset(0),
          mMethod(AllocationMethod::kStandalone),
          mBlock(nullptr),
          mMappedPointer(mappedPointer) {
    }

    bool MemoryAllocation::operator==(const MemoryAllocation& other) const {
        return (other.mAllocator == mAllocator && other.mMemory == mMemory &&
                other.mOffset == mOffset && other.mMethod == mMethod && other.mBlock == mBlock);
    }

    bool MemoryAllocation::operator!=(const MemoryAllocation& other) const {
        return !operator==(other);
    }

    MemoryBase* MemoryAllocation::GetMemory() const {
        return mMemory;
    }

    uint8_t* MemoryAllocation::GetMappedPointer() const {
        return mMappedPointer;
    }

    void MemoryAllocation::Reset() {
        mAllocator = nullptr;
        mMemory = nullptr;
        mMappedPointer = nullptr;
        mOffset = kInvalidOffset;
        mMethod = AllocationMethod::kUndefined;
        mBlock = nullptr;
    }

    MemoryAllocator* MemoryAllocation::GetAllocator() const {
        return mAllocator;
    }

    void MemoryAllocation::SetAllocator(MemoryAllocator* allocator) {
        mAllocator = allocator;
    }

    uint64_t MemoryAllocation::GetSize() const {
        switch (mMethod) {
            case gpgmm::AllocationMethod::kStandalone:
                ASSERT(mMemory != nullptr);
                return mMemory->GetSize();
            case gpgmm::AllocationMethod::kSubAllocated:
            case gpgmm::AllocationMethod::kSubAllocatedWithin: {
                ASSERT(mBlock != nullptr);
                return mBlock->Size;
            }
            default: {
                UNREACHABLE();
                return kInvalidSize;
            }
        }
    }

    uint64_t MemoryAllocation::GetOffset() const {
        return mOffset;
    }

    AllocationMethod MemoryAllocation::GetMethod() const {
        return mMethod;
    }

    Block* MemoryAllocation::GetBlock() const {
        return mBlock;
    }

}  // namespace gpgmm
