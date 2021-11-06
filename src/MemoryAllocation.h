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

#include <cstdint>

namespace gpgmm {

    struct Block;
    class MemoryBase;
    class MemoryAllocator;

    // Represents how memory was allocated.
    enum class AllocationMethod {

        // Memory not sub-divided.
        kStandalone,

        // Memory sub-divided using one or more blocks.
        kSubAllocated,

        // Memory not allocated or freed.
        kUndefined
    };

    // Metadata that describes how the allocation was allocated.
    struct AllocationInfo {
        // AllocationInfo contains a separate offset to not confuse block vs memory offsets.
        // The block offset is within the entire allocator memory range and only required by the
        // buddy sub-allocator to get the corresponding memory. Unlike the block offset, the
        // allocation offset is always local to the memory.
        Block* Block = nullptr;

        AllocationMethod Method = AllocationMethod::kUndefined;
    };

    // Represents a location in memory.
    class MemoryAllocation {
      public:
        MemoryAllocation();
        MemoryAllocation(MemoryAllocator* allocator,
                         const AllocationInfo& info,
                         uint64_t offset,
                         MemoryBase* memory,
                         uint8_t* mappedPointer = nullptr);
        virtual ~MemoryAllocation() = default;

        MemoryAllocation(const MemoryAllocation&) = default;
        MemoryAllocation& operator=(const MemoryAllocation&) = default;
        bool operator==(const MemoryAllocation&);
        bool operator!=(const MemoryAllocation& other);

        MemoryBase* GetMemory() const;
        uint64_t GetOffset() const;
        uint8_t* GetMappedPointer() const;
        AllocationInfo GetInfo() const;
        MemoryAllocator* GetAllocator() const;

      protected:
        friend class MemoryAllocator;

        bool IsSubAllocated() const;
        void AddSubAllocatedRef();
        void ReleaseSubAllocatedRef();

        virtual void Reset();

      private:
        MemoryAllocator* mAllocator;
        AllocationInfo mInfo;
        uint64_t mOffset;
        MemoryBase* mMemory;
        uint8_t* mMappedPointer;
    };
}  // namespace gpgmm

#endif  // GPGMM_MEMORYALLOCATION_H_
