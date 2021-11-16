// Copyright 2018 The Dawn Authors
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

#ifndef GPGMM_MEMORYALLOCATION_H_
#define GPGMM_MEMORYALLOCATION_H_

#include "common/Limits.h"

#include <cstdint>

namespace gpgmm {

    struct Block;

    // Represents how memory was allocated.
    enum class AllocationMethod {

        // Not sub-divided.
        kStandalone,

        // Sub-divided using one or more memory allocations.
        kSubAllocated,

        // Sub-divided within a single memory allocation.
        kSubAllocatedWithin,

        // Not yet allocated or invalid.
        kUndefined
    };

    class MemoryBase;
    class MemoryAllocator;

    // Represents a location in memory.
    class MemoryAllocation {
      public:
        MemoryAllocation();

        // Constructs a sub-allocated memory allocation.
        MemoryAllocation(MemoryAllocator* allocator,
                         MemoryBase* memory,
                         uint64_t offset,
                         AllocationMethod method,
                         Block* block,
                         uint8_t* mappedPointer = nullptr);

        // Constructs a standalone memory allocation.
        MemoryAllocation(MemoryAllocator* allocator,
                         MemoryBase* memory,
                         uint8_t* mappedPointer = nullptr);

        virtual ~MemoryAllocation() = default;

        MemoryAllocation(const MemoryAllocation&) = default;
        MemoryAllocation& operator=(const MemoryAllocation&) = default;
        bool operator==(const MemoryAllocation&) const;
        bool operator!=(const MemoryAllocation& other) const;

        MemoryBase* GetMemory() const;
        uint8_t* GetMappedPointer() const;
        MemoryAllocator* GetAllocator() const;
        uint64_t GetSize() const;
        uint64_t GetOffset() const;
        AllocationMethod GetMethod() const;
        Block* GetBlock() const;

      protected:
        friend class MemoryAllocator;

        virtual void Reset();

      private:
        MemoryAllocator* mAllocator;
        MemoryBase* mMemory;

        // AllocationInfo contains a separate offset to not confuse block vs memory offsets.
        // The block offset is within the entire allocator memory range and only required by the
        // sub-allocator to get the corresponding memory. Unlike the block offset, the
        // allocation offset is always local to the memory.
        uint64_t mOffset;
        AllocationMethod mMethod;
        Block* mBlock;

        uint8_t* mMappedPointer;
    };
}  // namespace gpgmm

#endif  // GPGMM_MEMORYALLOCATION_H_
