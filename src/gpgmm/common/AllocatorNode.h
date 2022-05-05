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

#ifndef GPGMM_COMMON_ALLOCATORNODE_H_
#define GPGMM_COMMON_ALLOCATORNODE_H_

#include "gpgmm/utils/LinkedList.h"

#include <memory>

namespace gpgmm {

    // Stores allocators as a doubly-linked list.
    // A allocator becomes a linked node where allocations made between the parent and the next
    // allocator form a one-way edge (ie. child sub-allocates parent's allocation). This results in
    // trivial lifetime management and traversals.
    template <typename T>
    class AllocatorNode : public LinkNode<T> {
      public:
        AllocatorNode() = default;
        explicit AllocatorNode(std::unique_ptr<T> next);
        virtual ~AllocatorNode();

        T* GetNextInChain() const;
        T* GetParent() const;

      private:
        T* InsertIntoChain(std::unique_ptr<T> next);

        LinkedList<T> mNext;
        T* mParent = nullptr;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_ALLOCATORNODE_H_
