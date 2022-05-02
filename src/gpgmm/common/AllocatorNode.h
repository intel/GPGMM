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

    // Stores allocators in a directed-acyclic-graph using an adjacency list representation.
    // A allocator becomes a linked node where allocations made between the parent and child
    // allocators form a one-way edge (ie. child sub-allocates parent's allocation). This results in
    // trivial lifetime management and traversals: child allocators cannot outlive parents and
    // queries are done through post-order and post-order searches, respectively.
    template <typename T>
    class AllocatorNode : public LinkNode<T> {
      public:
        virtual ~AllocatorNode();

      protected:
        bool HasChild() const;
        T* GetFirstChild() const;
        T* GetParent() const;
        T* AppendChild(std::unique_ptr<T> obj);
        std::unique_ptr<T> RemoveChild(T* ptr);

        // TODO: Make LinkedList iterable to protect.
        LinkedList<T> mChildren;

      private:
        T* mParent = nullptr;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_ALLOCATORNODE_H_
