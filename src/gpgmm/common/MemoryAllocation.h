// Copyright 2018 The Dawn Authors
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

#ifndef SRC_GPGMM_COMMON_MEMORYALLOCATION_H_
#define SRC_GPGMM_COMMON_MEMORYALLOCATION_H_

#include "gpgmm/common/Object.h"
#include "gpgmm/utils/Limits.h"

#define GPGMM_INVALID_ALLOCATION \
    MemoryAllocationBase {       \
    }

namespace gpgmm {

    // Represents how memory was allocated.
    enum class AllocationMethod {

        // Not yet allocated or invalid.
        kUndefined = 0,

        // Not sub-divided.
        kStandalone = 1,

        // Sub-divided using one or more allocations.
        kSubAllocated = 2,

        // Sub-divided within a single memory allocation.
        kSubAllocatedWithin = 3,
    };

    class MemoryBase;
    struct MemoryBlock;
    class MemoryAllocatorBase;

    // Represents a location and range in memory.
    class MemoryAllocationBase : public ObjectBase {
      public:
        // Contructs an invalid memory allocation.
        MemoryAllocationBase();

        // Constructs a "sub-allocated" memory allocation.
        MemoryAllocationBase(MemoryAllocatorBase* allocator,
                             MemoryBase* memory,
                             uint64_t offset,
                             AllocationMethod method,
                             MemoryBlock* block,
                             uint64_t requestSize);

        // Constructs a "standalone" memory allocation.
        MemoryAllocationBase(MemoryAllocatorBase* allocator,
                             MemoryBase* memory,
                             uint64_t requestSize);

        virtual ~MemoryAllocationBase() override = default;

        MemoryAllocationBase(const MemoryAllocationBase&) = default;
        MemoryAllocationBase& operator=(const MemoryAllocationBase&) = default;
        bool operator==(const MemoryAllocationBase&) const;
        bool operator!=(const MemoryAllocationBase& other) const;

        MemoryBase* GetMemory() const;
        MemoryAllocatorBase* GetAllocator() const;
        uint64_t GetSize() const;
        uint64_t GetRequestSize() const;
        uint64_t GetAlignment() const;
        uint64_t GetOffset() const;
        AllocationMethod GetMethod() const;
        MemoryBlock* GetBlock() const;
        bool IsRequestedSizeMisaligned() const;

      protected:
        friend class MemoryAllocatorBase;

        MemoryAllocatorBase* mAllocator;

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(MemoryAllocationBase)

        MemoryBase* mMemory;
        uint64_t mOffset;  // Offset always local to the memory.
        AllocationMethod mMethod;

#ifdef GPGMM_ENABLE_MEMORY_ALIGN_CHECKS
        uint64_t mRequestSize;
#endif

        MemoryBlock* mBlock;
    };
}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_MEMORYALLOCATION_H_
