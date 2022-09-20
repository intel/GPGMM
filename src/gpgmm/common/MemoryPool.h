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

#ifndef GPGMM_COMMON_MEMORYPOOL_H_
#define GPGMM_COMMON_MEMORYPOOL_H_

#include "gpgmm/common/MemoryAllocation.h"
#include "gpgmm/utils/Limits.h"

#include <memory>

namespace gpgmm {

    /** \struct MemoryPoolInfo
    Additional information about the memory pool.
    */
    struct MemoryPoolInfo {
        /** \brief Total size of the pool, in bytes.
         */
        uint64_t SizeInBytes;
    };

    /** \brief Stores a collection of memory allocations.

    Memory allocations stored in the pool must ALL be in the same state (ex. "free pool").

    To grow the pool, created memory allocations are inserted into the pool by ReturnToPool().

    To shrink the pool, existing allocations can removed out by AcquireFromPool() or de-allocated
    together by ReleasePool().
    */
    class MemoryPool {
      public:
        /** \brief Constructs a pool for memory of the specified size.

        @param memorySize Size, in bytes, of the memory allocation stored in the pool.
        */
        explicit MemoryPool(uint64_t memorySize);
        virtual ~MemoryPool();

        /** \brief Retrieves a memory allocation from the pool using an optional index.

        @param indexInPool Optional index of the memory allocation to retrieve.
        */
        virtual MemoryAllocation AcquireFromPool(uint64_t indexInPool = kInvalidIndex) = 0;

        /** \brief Returns a memory allocation back to the pool using an optional index.

        @param allocation A pointer to MemoryAllocation which will be returned.
        @param indexInPool Optional index of the memory allocation to return.
        */
        virtual void ReturnToPool(MemoryAllocation allocation,
                                  uint64_t indexInPool = kInvalidIndex) = 0;

        /** \brief Deallocate or shrink the pool.

        @param bytesToRelease Optional size, in bytes, to release from the pool. If no size is
        specified or kInvalidSize, the entire pool will be released.

        \return Total amount, in bytes, released by the pool.
        */
        virtual uint64_t ReleasePool(uint64_t bytesToRelease = kInvalidSize) = 0;

        /** \brief Get the size of the pool.

        \return Number of memory allocations in the pool.
        */
        virtual uint64_t GetPoolSize() const = 0;

        /** \brief Returns the size of the memory allocations being pooled.

        \return Size, in bytes, of the memory allocation being pooled.
        */
        virtual uint64_t GetMemorySize() const;

        /** \brief Returns information about this memory pool.

        \return A MemoryPoolInfo struct containing the information.
        */
        MemoryPoolInfo GetInfo() const;

        /** \brief Returns the class name of this allocation.

        \return A pointer to a C character string with data, "MemoryPool".
        */
        const char* GetTypename() const;

      protected:
        // Shrinks the size of the pool in |mMemorySize| sizes until |bytesToRelease| is reached.
        template <typename T>
        uint64_t TrimPoolUntil(T& pool, uint64_t bytesToRelease) {
            uint64_t totalBytesReleased = 0;
            uint64_t lastIndex = 0;
            for (auto& allocation : pool) {
                totalBytesReleased += allocation.GetSize();
                allocation.GetAllocator()->DeallocateMemory(
                    std::make_unique<MemoryAllocation>(allocation));
                lastIndex++;
                if (totalBytesReleased >= bytesToRelease) {
                    break;
                }
            }

            // Last is non-inclusive or [first, last).
            if (lastIndex > 0) {
                pool.erase(pool.begin(), pool.begin() + lastIndex);
            }

            return totalBytesReleased;
        }

      private:
        uint64_t mMemorySize;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORYPOOL_H_
