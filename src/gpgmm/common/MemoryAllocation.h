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

    /** \struct MEMORY_ALLOCATION_INFO
    Additional information about the memory allocation.
    */
    struct MEMORY_ALLOCATION_INFO {
        /** \brief The created size of the memory allocation, in bytes.

        Must be non-zero.
        */
        uint64_t SizeInBytes;

        /** \brief The offset relative to memory, in bytes.
         */
        uint64_t Offset;

        /** \brief The method to describe how the allocation was created.

        The Method determines how to figure out the size of the allocation.
        */
        AllocationMethod Method;

        /** \brief Pointer to underlying memory object.

        Must be valid for the duration of the allocation.
        */
        MemoryBase* Memory;

        /** \brief Pointer to allocator that created this allocation.

        Must be valid for the duration of the allocation.
        */
        MemoryAllocator* Allocator;
    };

    /** \brief Represents a location and range in memory.

    It can represent a allocation in memory one of two ways: 1) a range within a memory block or 2)
    a memory block of the entire memory range.

    MemoryAllocation is meant to be handle like interface and should not be used directly.
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
        @param mappedPointer A pointer to uint8_t which is mapped by the allocation.
        */
        MemoryAllocation(MemoryAllocator* allocator,
                         MemoryBase* memory,
                         uint64_t offset,
                         AllocationMethod method,
                         MemoryBlock* block,
                         uint8_t* mappedPointer = nullptr);

        /** \brief Constructs a "standalone" memory allocation.

        A standalone memory allocation is a zero offset, entire range, of memory.

        @param allocator A pointer to the allocator responsible for creating the memory block.
        @param memory A pointer to the underlying MemoryBase that will contain the memory
        allocation.
        @param mappedPointer A pointer to uint8_t which is mapped by the allocation.
        */
        MemoryAllocation(MemoryAllocator* allocator,
                         MemoryBase* memory,
                         uint8_t* mappedPointer = nullptr);

        virtual ~MemoryAllocation() = default;

        MemoryAllocation(const MemoryAllocation&) = default;
        MemoryAllocation& operator=(const MemoryAllocation&) = default;
        bool operator==(const MemoryAllocation&) const;
        bool operator!=(const MemoryAllocation& other) const;

        /** \brief Returns information about this memory allocation.

        \return A MEMORY_ALLOCATION_INFO struct containing the information.
        */
        MEMORY_ALLOCATION_INFO GetInfo() const;

        /** \brief Returns the memory assigned to this allocation.

        \return A pointer to the MemoryBase used by this allocation.
        */
        MemoryBase* GetMemory() const;

        /** \brief Returns a byte addressable pointer mapped by this allocation.

        \return A pointer to uint8_t which is mapped by the allocation.
        */
        uint8_t* GetMappedPointer() const;

        /** \brief Returns the allocator responsible for allocating the memory for this allocation.

        \return A pointer to MemoryAllocator which is the allocator used.
        */
        MemoryAllocator* GetAllocator() const;

        /** \brief The size, in bytes, of the memory allocation.

        \return The size, in bytes, of the allocation.
        */
        uint64_t GetSize() const;

        /** \brief The offset, in bytes, where the memory allocation was allocated in memory.

        \return The offset, in bytes, of the allocation.
        */
        uint64_t GetOffset() const;

        /** \brief The method to describe how the allocation was created.

        The Method determines how to figure out the size of the allocation.

        \return The method used to create memory for this allocation.
        */
        AllocationMethod GetMethod() const;

        /** \brief The block used to assign a range of memory for this allocation.

        \Return A pointer to the MemoryBlock.
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

        uint8_t* mMappedPointer;
    };
}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORYALLOCATION_H_
