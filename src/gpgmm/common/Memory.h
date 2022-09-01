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

#ifndef GPGMM_COMMON_MEMORY_H_
#define GPGMM_COMMON_MEMORY_H_

#include "gpgmm/utils/RefCount.h"

namespace gpgmm {

    class MemoryPool;

    /** \brief Represents a memory object.

    When memory is sub-allocated, it will have a non-zero refcount.
    */
    class MemoryBase {
      public:
        /** \brief Constructs a memory object of the specified size and alignment.

        @param size Size, in bytes, of the memory object.
        @param alignment Alignment, in bytes, of the memory object.
        */
        explicit MemoryBase(uint64_t size, uint64_t alignment);
        virtual ~MemoryBase();

        /** \brief Return the size of the memory object.

        \return Size, in bytes, of the memory object.
        */
        uint64_t GetSize() const;

        /** \brief Return the alignment of the memory object.

        \return Alignment, in bytes, of the memory object.
        */
        uint64_t GetAlignment() const;

        /** \brief Get the memory pool managing the object.

        \return A pointer to MemoryPool managing this memory object.
        */
        MemoryPool* GetPool() const;

        /** \brief Set the memory pool to manage this object.

        @param pool A pointer to MemoryPool used to manage this object.
        */
        void SetPool(MemoryPool* pool);

        /** \brief Increments the sub-allocation reference count on the heap.
         */
        void AddSubAllocationRef();

        /** \brief Decrements the sub-allocation reference count on the heap.
         */
        bool RemoveSubAllocationRef();

      private:
        RefCounted mSubAllocationRefs;

        const uint64_t mSize;
        const uint64_t mAlignment;

        MemoryPool* mPool = nullptr;  // nullptr means no pool is assigned.
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORY_H_
