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

#ifndef GPGMM_COMMON_MEMORYALLOCATION_H_
#define GPGMM_COMMON_MEMORYALLOCATION_H_

#include "gpgmm/utils/Limits.h"

#include <gpgmm.h>

namespace gpgmm {

    class MemoryBase;
    struct MemoryBlock;
    class MemoryAllocator;

    // Represents a location and range in memory.
    class MemoryAllocation {
      public:
        // Contructs an invalid memory allocation.
        MemoryAllocation();

        // Constructs a "sub-allocated" memory allocation.
        MemoryAllocation(MemoryAllocator* allocator,
                         MemoryBase* memory,
                         uint64_t offset,
                         AllocationMethod method,
                         MemoryBlock* block,
                         uint64_t requestSize);

        // Constructs a "standalone" memory allocation.
        MemoryAllocation(MemoryAllocator* allocator, MemoryBase* memory, uint64_t requestSize);

        virtual ~MemoryAllocation() = default;

        MemoryAllocation(const MemoryAllocation&) = default;
        MemoryAllocation& operator=(const MemoryAllocation&) = default;
        bool operator==(const MemoryAllocation&) const;
        bool operator!=(const MemoryAllocation& other) const;

        MemoryBase* GetMemory() const;
        MemoryAllocator* GetAllocator() const;
        uint64_t GetSize() const;
        uint64_t GetRequestSize() const;
        uint64_t GetAlignment() const;
        uint64_t GetOffset() const;
        AllocationMethod GetMethod() const;
        MemoryBlock* GetBlock() const;

      protected:
        friend class MemoryAllocator;

        MemoryAllocator* mAllocator;

      private:
        MemoryBase* mMemory;
        uint64_t mOffset;  // Offset always local to the memory.
        AllocationMethod mMethod;

#ifdef GPGMM_ENABLE_MEMORY_ALIGN_CHECKS
        uint64_t mRequestSize;
#endif

        MemoryBlock* mBlock;
    };
}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORYALLOCATION_H_
