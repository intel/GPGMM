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

    /** \brief AllocatorNode stores one or more allocators in a intrusive LinkedList.

    AllocatorNode can also be created with another AllocatorNode. AllocatorNode represents
    a chain where allocations made between the first-order AllocatorNode (or parent)
    and the next AllocatorNode (or child) form a one-way edge.
    */
    template <typename T>
    class AllocatorNode : public LinkNode<T> {
      public:
        /** \brief Construct a AllocatorNode.
         */
        AllocatorNode() = default;

        /** \brief Constructs a AllocatorNode using another AllocatorNode.

        @param next Pointer of next node to add to chain.
        */
        explicit AllocatorNode(std::unique_ptr<T> next);

        /** \brief Destruct a AllocatorNode.

        If the AllocatorNode was in a LinkedList, it will be removed.
        If the AllocatorNode was connected, it will destroy them before itself.
        */
        virtual ~AllocatorNode();

        /** \brief Return the next AllocatorNode.

        \return Pointer of next node in chain.
        */
        T* GetNextInChain() const;

        /** \brief Return the previous AllocatorNode.

        \return Pointer of previous node in chain.
        */
        T* GetParent() const;

      private:
        void InsertIntoChain(std::unique_ptr<T> next);

        AllocatorNode<T>* mNext = nullptr;
        T* mParent = nullptr;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_ALLOCATORNODE_H_
