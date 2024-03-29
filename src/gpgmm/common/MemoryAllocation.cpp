// Copyright 2019 The Dawn Authors
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

#include "gpgmm/common/MemoryAllocation.h"

#include "gpgmm/common/Memory.h"
#include "gpgmm/common/MemoryBlock.h"
#include "gpgmm/utils/Assert.h"

namespace gpgmm {

    MemoryAllocationBase::MemoryAllocationBase()
        : mAllocator(nullptr),
          mMemory(nullptr),
          mOffset(kInvalidOffset),
          mMethod(AllocationMethod::kUndefined),
#ifdef GPGMM_ENABLE_MEMORY_ALIGN_CHECKS
          mRequestSize(kInvalidSize),
#endif
          mBlock(nullptr) {
    }

    MemoryAllocationBase::MemoryAllocationBase(MemoryAllocatorBase* allocator,
                                               MemoryBase* memory,
                                               uint64_t offset,
                                               AllocationMethod method,
                                               MemoryBlock* block,
                                               uint64_t requestSize)
        : mAllocator(allocator),
          mMemory(memory),
          mOffset(offset),
          mMethod(method),
#ifdef GPGMM_ENABLE_MEMORY_ALIGN_CHECKS
          mRequestSize(requestSize),
#endif
          mBlock(block) {
    }

    MemoryAllocationBase::MemoryAllocationBase(MemoryAllocatorBase* allocator,
                                               MemoryBase* memory,
                                               uint64_t requestSize)
        : mAllocator(allocator),
          mMemory(memory),
          mOffset(0),
          mMethod(AllocationMethod::kStandalone),
#ifdef GPGMM_ENABLE_MEMORY_ALIGN_CHECKS
          mRequestSize(requestSize),
#endif
          mBlock(nullptr) {
    }

    bool MemoryAllocationBase::operator==(const MemoryAllocationBase& other) const {
        return (other.mAllocator == mAllocator && other.mMemory == mMemory &&
                other.mOffset == mOffset && other.mMethod == mMethod && other.mBlock == mBlock);
    }

    bool MemoryAllocationBase::operator!=(const MemoryAllocationBase& other) const {
        return !operator==(other);
    }

    MemoryBase* MemoryAllocationBase::GetMemory() const {
        return mMemory;
    }

    MemoryAllocatorBase* MemoryAllocationBase::GetAllocator() const {
        return mAllocator;
    }

    uint64_t MemoryAllocationBase::GetSize() const {
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

    uint64_t MemoryAllocationBase::GetRequestSize() const {
#ifdef GPGMM_ENABLE_MEMORY_ALIGN_CHECKS
        return mRequestSize;
#else
        return kInvalidSize;
#endif
    }

    uint64_t MemoryAllocationBase::GetAlignment() const {
        switch (mMethod) {
            case gpgmm::AllocationMethod::kStandalone:
                ASSERT(mMemory != nullptr);
                return mMemory->GetAlignment();
            // Sub-allocation cannot be further divided and must have a alignment equal to the
            // the size.
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

    uint64_t MemoryAllocationBase::GetOffset() const {
        return mOffset;
    }

    AllocationMethod MemoryAllocationBase::GetMethod() const {
        return mMethod;
    }

    MemoryBlock* MemoryAllocationBase::GetBlock() const {
        return mBlock;
    }

    bool MemoryAllocationBase::IsRequestedSizeMisaligned() const {
        return GetRequestSize() != kInvalidSize && GetSize() > GetRequestSize();
    }

    void MemoryAllocationBase::SetOffset(uint64_t offset) {
        mOffset = offset;
    }

    void MemoryAllocationBase::SetMethod(AllocationMethod method) {
        mMethod = method;
    }

    void MemoryAllocationBase::SetAllocator(MemoryAllocatorBase* allocator) {
        mAllocator = allocator;
    }

    void MemoryAllocationBase::SetBlock(MemoryBlock* block) {
        mBlock = block;
    }

}  // namespace gpgmm
