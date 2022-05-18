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

    /** \brief  Chain together allocators as a doubly linked list.

    A allocator becomes a node in a linked-list where allocations made between the parent and the
    child allocator form a one-way edge (child sub-allocates parent's allocation).

    This scheme results in trivial lifetime management and traversals between multiple allocators
    that depend on each other.
    */
    template <typename T>
    class AllocatorNode : public LinkNode<T> {
      public:
        /** \brief Construct the node without a child.
         */
        AllocatorNode() = default;

        /** \brief Construct the node as a parent or with a child.

        @param next Pointer to the next or child node.
        */
        explicit AllocatorNode(std::unique_ptr<T> next);

        virtual ~AllocatorNode();

        /** \brief Returns the next node in the chain.

        \return Pointer to the child or next node. NULL if none exists.
        */
        T* GetNextInChain() const;

        /** \brief Returns the next node in the chain.

        \return Pointer to the parent or previous node. NULL if none exists
        */
        T* GetParent() const;

      private:
        T* InsertIntoChain(std::unique_ptr<T> next);
        T* mParent = nullptr;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_ALLOCATORNODE_H_
