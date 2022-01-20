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

#include "gpgmm/GraphNode.h"

#include "gpgmm/MemoryAllocator.h"

namespace gpgmm {

    template <typename T>
    GraphNode<T>::~GraphNode() {
        // Deletes adjacent node recursively (post-order).
        auto* curr = mChildren.head();
        while (curr != mChildren.end()) {
            auto* next = curr->next();
            delete curr->value();
            curr = next;
        }

        if (LinkNode<T>::IsInList()) {
            LinkNode<T>::RemoveFromList();
        }

        ASSERT(!HasChild());
    }

    template <typename T>
    bool GraphNode<T>::HasChild() const {
        return !mChildren.empty();
    }

    template <typename T>
    T* GraphNode<T>::GetFirstChild() const {
        if (mChildren.head() == nullptr) {
            return nullptr;
        }
        return mChildren.head()->value();
    }

    template <typename T>
    T* GraphNode<T>::AppendChild(std::unique_ptr<T> obj) {
        ASSERT(obj != nullptr);
        mChildren.Append(obj.release());
        return mChildren.tail()->value();
    }

    // Explictly instantiate the template to ensure the compiler has the
    // definition of the require type outside of this file.
    template class GraphNode<MemoryAllocator>;

}  // namespace gpgmm
