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

#ifndef SRC_GPGMM_COMMON_MEMORYPOOL_H_
#define SRC_GPGMM_COMMON_MEMORYPOOL_H_

#include "gpgmm/common/Error.h"
#include "gpgmm/common/MemoryAllocation.h"
#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/utils/Limits.h"

#include <memory>

namespace gpgmm {

    // Stores a collection of memory allocations.
    class MemoryPoolBase : public ObjectBase {
      public:
        // Constructs a pool for memory of the specified size.
        explicit MemoryPoolBase(uint64_t memorySize);
        virtual ~MemoryPoolBase() override;

        // Retrieves a memory allocation from the pool using an optional index.
        // Use kInvalidIndex to specify |this| pool is not indexed.
        virtual ResultOrError<std::unique_ptr<MemoryAllocationBase>> AcquireFromPool(
            uint64_t indexInPool) = 0;

        std::unique_ptr<MemoryAllocationBase> AcquireFromPoolForTesting(uint64_t indexInPool);

        // Returns a memory allocation back to the pool using an optional index.
        // Use kInvalidIndex to specify |this| pool is not indexed.
        virtual MaybeError ReturnToPool(std::unique_ptr<MemoryAllocationBase> allocation,
                                        uint64_t indexInPool) = 0;

        // Deallocate or shrink the pool.
        virtual uint64_t ReleasePool(uint64_t bytesToRelease) = 0;

        // Gets the number of allocations in the pool.
        virtual uint64_t GetPoolSize() const = 0;

        // Returns the size of the memory allocations being pooled.
        virtual uint64_t GetMemorySize() const;

      protected:
        // Shrinks the size of the pool in |mMemorySize| sizes until |bytesToRelease| is reached.
        template <typename MemoryPoolT>
        uint64_t DeallocateAndShrinkUntil(MemoryPoolT* pool, uint64_t bytesToRelease) {
            uint64_t bytesReleased = 0;
            uint64_t lastIndexInPool = 0;
            for (auto& allocation : *pool) {
                bytesReleased += allocation->GetSize();
                allocation->GetAllocator()->DeallocateMemory(std::move(allocation));
                lastIndexInPool++;
                if (bytesReleased >= bytesToRelease) {
                    break;
                }
            }

            // Last is non-inclusive or [first, last).
            if (lastIndexInPool > 0) {
                pool->ResizePool(lastIndexInPool);
            }

            return bytesReleased;
        }

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(MemoryPoolBase)

        const uint64_t mMemorySize;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_MEMORYPOOL_H_
