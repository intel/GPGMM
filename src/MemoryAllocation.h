// Copyright 2018 The Dawn Authors
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

#define GPGMM_INVALID_ALLOCATION \
    MemoryAllocation {           \
    }

namespace gpgmm {

    class MemoryBase;
    class AllocatorBase;

    // Allocation method determines how memory was sub-divided.
    // Used by the device to get the allocator that was responsible for the allocation.
    enum class AllocationMethod {

        // Memory not sub-divided.
        kDirect,

        // Memory sub-divided using one or more blocks of various sizes.
        kSubAllocated,

        // Memory not allocated or freed.
        kInvalid
    };

    // Metadata that describes how the allocation was allocated.
    struct AllocationInfo {
        // AllocationInfo contains a separate offset to not confuse block vs memory offsets.
        // The block offset is within the entire allocator memory range and only required by the
        // buddy sub-allocator to get the corresponding memory. Unlike the block offset, the
        // allocation offset is always local to the memory.
        uint64_t mBlockOffset = 0;

        AllocationMethod mMethod = AllocationMethod::kInvalid;
    };

    // Handle into a resource heap pool.
    class MemoryAllocation {
      public:
        MemoryAllocation();
        MemoryAllocation(AllocatorBase* allocator,
                         const AllocationInfo& info,
                         uint64_t offset,
                         MemoryBase* memory,
                         uint8_t* mappedPointer = nullptr);
        virtual ~MemoryAllocation() = default;

        MemoryAllocation(const MemoryAllocation&) = default;
        MemoryAllocation& operator=(const MemoryAllocation&) = default;
        bool operator==(const MemoryAllocation&);

        MemoryBase* GetMemory() const;
        uint64_t GetOffset() const;
        uint8_t* GetMappedPointer() const;
        AllocationInfo GetInfo() const;
        AllocatorBase* GetAllocator();

        virtual void Invalidate();

      private:
        AllocatorBase* mAllocator;
        AllocationInfo mInfo;
        uint64_t mOffset;
        MemoryBase* mMemory;
        uint8_t* mMappedPointer;
    };
}  // namespace gpgmm

#endif  // GPGMM_MEMORYALLOCATION_H_
