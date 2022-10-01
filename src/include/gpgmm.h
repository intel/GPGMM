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

#ifndef INCLUDE_GPGMM_H_
#define INCLUDE_GPGMM_H_

#include <cstdint>

namespace gpgmm {

    /** \brief Stores a collection of memory allocations.
     */
    class IMemoryPool {};

    class IMemoryObject {
      public:
        virtual ~IMemoryObject() = default;

        /** \brief Return the size of the memory object.

        \return Size, in bytes, of the memory object.
        */
        virtual uint64_t GetSize() const = 0;

        /** \brief Return the alignment of the memory object.

        \return Alignment, in bytes, of the memory object.
        */
        virtual uint64_t GetAlignment() const = 0;

        /** \brief Increments the sub-allocation reference count on the heap.
         */
        virtual void AddSubAllocationRef() = 0;

        /** \brief Decrements the sub-allocation reference count on the heap.
         */
        virtual bool RemoveSubAllocationRef() = 0;

        /** \brief Get the pool this memory is contained in.
         */
        virtual IMemoryPool* GetPool() const = 0;

        /** \brief Assign the pool this memory is contained in.
         */
        virtual void SetPool(IMemoryPool* pool) = 0;
    };

    /** \struct MemoryAllocatorStats
        Information about the memory allocator.
        */
    struct MemoryAllocatorStats {
        /** \brief Number of used sub-allocated blocks within the same memory.
         */
        uint32_t UsedBlockCount;

        /** \brief Total size, in bytes, of used sub-allocated blocks.
         */
        uint64_t UsedBlockUsage;

        /** \brief Number of used memory allocations.
         */
        uint32_t UsedMemoryCount;

        /** \brief Total size, in bytes, of used memory.
         */
        uint64_t UsedMemoryUsage;

        /** \brief Total size, in bytes, of free memory.
         */
        uint64_t FreeMemoryUsage;

        /** \brief Cache misses not eliminated by prefetching.
         */
        uint64_t PrefetchedMemoryMisses;

        /** \brief Cache misses eliminated because of prefetching.
         */
        uint64_t PrefetchedMemoryMissesEliminated;

        /** \brief Requested size was NOT cached.
         */
        uint64_t SizeCacheMisses;

        /** \brief Requested size was cached.
         */
        uint64_t SizeCacheHits;

        /** \brief Adds or sums together two infos.
         */
        MemoryAllocatorStats& operator+=(const MemoryAllocatorStats& rhs);
    };

    /** \enum AllocationMethod
    Represents how memory was allocated.
    */
    enum class AllocationMethod {

        /** \brief Not yet allocated or invalid.

        This is an invalid state that assigned temporary before the actual method is known.
        */
        kUndefined = 0,

        /** \brief Not sub-divided.

        One and only one allocation exists for the memory.
        */
        kStandalone = 1,

        /** \brief Sub-divided using one or more allocations.

        Underlying memory will be broken up into one or more memory allocations.
        */
        kSubAllocated = 2,

        /** \brief Sub-divided within a single memory allocation.

        A single memory allocation will be broken into one or more sub-allocations.
        */
        kSubAllocatedWithin = 3,
    };

}  // namespace gpgmm

#endif  // INCLUDE_GPGMM_H_
