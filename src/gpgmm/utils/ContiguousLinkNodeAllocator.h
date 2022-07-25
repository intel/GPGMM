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

#ifndef GPGMM_COMMON_CONTIGUOUSLINKNODEALLOCATOR_H_
#define GPGMM_COMMON_CONTIGUOUSLINKNODEALLOCATOR_H_

#include "gpgmm/utils/Assert.h"

#include <memory>
#include <utility>
#include <vector>

namespace gpgmm {

    // ContiguousLinkNodeAllocator is an allocator designed to store objects contiguously by storing
    // them in std::vectors of a fixed size. This class was specifically designed to be used with
    // the LinkNode type, which represents nodes in a LinkedList. By using this allocator, LinkNodes
    // are stored contiguously instead of in a fragmented manner, which reduces memory fragmentation
    // and pointer chasing when iterating a LinkedList.
    // Use placement new to allocate:
    //     T* objectPointer = (allocator.Allocate()) T();
    // Use the provided Deallocate to free the allocation for reuse:
    //     allocator.Deallocate(objectPointer);

    template <typename T>
    class ContiguousLinkNodeAllocator {
      public:
        explicit ContiguousLinkNodeAllocator(uint64_t objectsPerBlock)
            : mObjectsPerBlock(objectsPerBlock) {
        }

        using AllocationAddress = std::pair<uint64_t, uint64_t>;

        // Using this struct we can reinterpret_cast<T*> when we need to provide the allocation
        // pointer because it is the first object in the struct. We can
        // reinterpret_cast<ContiguousLinkNodeAllocation> back from the allocation pointer to get
        // the AllocationAddress indices needed during Deallocate().
        struct ContiguousLinkNodeAllocation {
            T object;
            AllocationAddress address;
        };

        T* Allocate() {
            // If a free allocation is available, reuse that location.
            if (!mFreeList.empty()) {
                AllocationAddress freeSpot = mFreeList[mFreeList.size() - 1];
                mFreeList.pop_back();
                return reinterpret_cast<T*>(&(*mAllocations[freeSpot.first])[freeSpot.second]);
            }

            // If our next allocation offset starts with a zero it means we haven't allocated the
            // block yet. Allocate it.
            if (mNextAllocation.second == 0) {
                mAllocations.push_back(std::unique_ptr<std::vector<ContiguousLinkNodeAllocation>>(
                    new std::vector<ContiguousLinkNodeAllocation>()));
                mAllocations[mNextAllocation.first]->reserve(mObjectsPerBlock);
            }

            // The indices for the allocation are stored on the allocation itself.
            (*mAllocations[mNextAllocation.first])[mNextAllocation.second].address =
                mNextAllocation;

            // We can reinterpret_cast<T*> from the ContiguousLinkNodeAllocation to get a pointer to
            // the actual object allocation on the ContiguousLinkNodeAllocation.
            T* allocationAddress = reinterpret_cast<T*>(
                &(*mAllocations[mNextAllocation.first])[mNextAllocation.second]);

            // Increment next allocation position.
            mNextAllocation.second++;
            if (mNextAllocation.second == mObjectsPerBlock) {
                mNextAllocation.first++;
                mNextAllocation.second = 0;
            }

            return allocationAddress;
        }

        void Deallocate(T* objectPointer) {
            ContiguousLinkNodeAllocation* allocation =
                reinterpret_cast<ContiguousLinkNodeAllocation*>(objectPointer);
            // Insert the AllocationAddress into the free list.
            mFreeList.push_back(allocation->address);
        }

      private:
        uint64_t mObjectsPerBlock;

        AllocationAddress mNextAllocation = {0, 0};

        std::vector<std::unique_ptr<std::vector<ContiguousLinkNodeAllocation>>> mAllocations;
        std::vector<AllocationAddress> mFreeList;
    };
}  // namespace gpgmm

#endif  // GPGMM_COMMON_CONTIGUOUSLINKNODEALLOCATOR_H_