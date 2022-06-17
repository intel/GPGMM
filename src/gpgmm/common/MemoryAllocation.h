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

#ifndef GPGMM_COMMON_MEMORYALLOCATION_H_
#define GPGMM_COMMON_MEMORYALLOCATION_H_

#include "gpgmm/utils/Limits.h"
#include "include/gpgmm_export.h"

#include <cstdint>

namespace gpgmm {

    /** \enum AllocationMethod
    Represents how memory was allocated.
    */
    enum AllocationMethod {

        /** \brief Not sub-divided.

        One and only one allocation exists for the memory.
        */
        kStandalone = 0x0,

        /** \brief Sub-divided using one or more allocations.

        Underlying memory will be broken up into one or more memory allocations.
        */
        kSubAllocated = 0x2,

        /** \brief Sub-divided within a single memory allocation.

        A single memory allocation will be broken into one or more sub-allocations.
        */
        kSubAllocatedWithin = 0x4,

        /** \brief Not yet allocated or invalid.

        This is an invalid state that assigned temporary before the actual method is known.
        */
        kUndefined = 0x8
    };

    struct MemoryBlock;
    class MemoryBase;
    class MemoryAllocator;

    /** \struct MemoryAllocationInfo
    Additional information about the memory allocation.
    */
    struct MemoryAllocationInfo {
        /** \brief Allocated size, in bytes, of the memory allocation.
        Must be non-zero. SizeInBytes is always a multiple of the alignment.
        */
        uint64_t SizeInBytes;

        /** \brief Allocated alignment, in bytes, of the memory allocation.

        Must be non-zero.
        */
        uint64_t Alignment;
    };

    /** \brief Represents a location and range in memory.

    It can represent a location in memory by one of two ways: 1) a range within a memory block or 2)
    a memory block of the entire memory range.
    */
    class GPGMM_EXPORT MemoryAllocation {
      public:
        /** \brief Contructs an invalid memory allocation.
         */
        MemoryAllocation();

        /** \brief Constructs a "sub-allocated" memory allocation.

        A sub-allocated memory allocation (or sub-allocation) is a non-zero offset, non-overlapping
        range, in memory.

        @param allocator A pointer to the allocator responsible for creating the memory block.
        @param memory A pointer to the underlying MemoryBase that will contain the memory
        allocation.
        @param offset The offset, in bytes, where the memory allocation was allocated in memory.
        @param method The method to describe how the allocation was created.
        @param block A pointer to a memory block within the resourceHeap, the placedResource was
        allocated from.
        @param requestSize The unaligned size, in bytes, of the size requested.
        @param mappedPointer A pointer to uint8_t which is mapped by the allocation.
        */
        MemoryAllocation(MemoryAllocator* allocator,
                         MemoryBase* memory,
                         uint64_t offset,
                         AllocationMethod method,
                         MemoryBlock* block,
                         uint64_t requestSize,
                         uint8_t* mappedPointer = nullptr);

        /** \brief Constructs a "standalone" memory allocation.

        A standalone memory allocation is a zero offset, entire range, of memory.

        @param allocator A pointer to the allocator responsible for creating the memory block.
        @param memory A pointer to the underlying MemoryBase that will contain the memory
        allocation.
        @param requestSize The unaligned size, in bytes, of the size requested.
        @param mappedPointer A pointer to uint8_t which is mapped by the allocation.
        */
        MemoryAllocation(MemoryAllocator* allocator,
                         MemoryBase* memory,
                         uint64_t requestSize,
                         uint8_t* mappedPointer = nullptr);

        virtual ~MemoryAllocation() = default;

        MemoryAllocation(const MemoryAllocation&) = default;
        MemoryAllocation& operator=(const MemoryAllocation&) = default;
        bool operator==(const MemoryAllocation&) const;
        bool operator!=(const MemoryAllocation& other) const;

        /** \brief Get the information about this memory allocation.

        \return A MemoryAllocationInfo struct containing the information.
        */
        MemoryAllocationInfo GetInfo() const;

        /** \brief Get the memory assigned to this allocation.

        \return A pointer to the MemoryBase used by this allocation.
        */
        MemoryBase* GetMemory() const;

        /** \brief Get the byte addressable pointer mapped by this allocation.

        \return A pointer to uint8_t which is mapped by the allocation.
        */
        uint8_t* GetMappedPointer() const;

        /** \brief Get the allocator responsible for allocating the memory for this allocation.

        \return A pointer to MemoryAllocator which is the allocator used.
        */
        MemoryAllocator* GetAllocator() const;

        /** \brief Get the size of the memory allocation.

        \return Size, in bytes, of the allocation.
        */
        uint64_t GetSize() const;

        /** \brief Get the requested size of the memory allocation.

        \return Size, in bytes, of the request used to create the memory allocation.
        */
        uint64_t GetRequestSize() const;

        /** \brief Get the alignment of the memory allocation.

        \return Alignment, in bytes, of the allocation.
        */
        uint64_t GetAlignment() const;

        /** \brief The offset, in bytes, where the memory allocation was allocated in memory.

        \return Offset, in bytes, of the allocation.
        */
        uint64_t GetOffset() const;

        /** \brief Get the method to describe how the allocation was created.

        The Method determines how to figure out the size of the allocation.

        \return AllocationMethod used to create memory for this allocation.
        */
        AllocationMethod GetMethod() const;

        /** \brief Get the block used to assign a range of memory for this allocation.

        \return A pointer to the MemoryBlock.
        */
        MemoryBlock* GetBlock() const;

      protected:
        friend class MemoryAllocator;

        MemoryAllocator* mAllocator;

      private:
        MemoryBase* mMemory;
        uint64_t mOffset;  // Offset always local to the memory.
        AllocationMethod mMethod;
        MemoryBlock* mBlock;

        uint64_t mRequestSize;
        uint8_t* mMappedPointer;
    };
}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORYALLOCATION_H_
