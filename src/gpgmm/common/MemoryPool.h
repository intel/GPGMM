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

#include "gpgmm/common/MemoryAllocation.h"
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
        virtual std::unique_ptr<MemoryAllocationBase> AcquireFromPool(uint64_t indexInPool) = 0;

        // Returns a memory allocation back to the pool using an optional index.
        // Use kInvalidIndex to specify |this| pool is not indexed.
        virtual void ReturnToPool(std::unique_ptr<MemoryAllocationBase> allocation,
                                  uint64_t indexInPool) = 0;

        // Deallocate or shrink the pool.
        virtual uint64_t ReleasePool(uint64_t bytesToRelease) = 0;

        // Get the size of the pool.
        virtual uint64_t GetPoolSize() const = 0;

        // Returns the size of the memory allocations being pooled.
        virtual uint64_t GetMemorySize() const;

      protected:
        // Shrinks the size of the pool in |mMemorySize| sizes until |bytesToRelease| is reached.
        template <typename T>
        uint64_t TrimPoolUntil(T& pool, uint64_t bytesToRelease) {
            uint64_t totalBytesReleased = 0;
            uint64_t lastIndex = 0;
            for (auto& allocation : pool) {
                totalBytesReleased += allocation->GetSize();
                allocation->ReleaseMemory();
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
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(MemoryPoolBase)

        const uint64_t mMemorySize;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_MEMORYPOOL_H_
