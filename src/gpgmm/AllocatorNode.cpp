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

#include "gpgmm/AllocatorNode.h"

#include "gpgmm/MemoryAllocator.h"

namespace gpgmm {

    template <typename T>
    AllocatorNode<T>::~AllocatorNode() {
        // Deletes adjacent node recursively (post-order).
        mChildren.DeleteAll();
        if (LinkNode<T>::IsInList()) {
            LinkNode<T>::RemoveFromList();
        }

        ASSERT(!HasChild());
    }

    template <typename T>
    bool AllocatorNode<T>::HasChild() const {
        return !mChildren.empty();
    }

    template <typename T>
    T* AllocatorNode<T>::GetFirstChild() const {
        if (mChildren.head() == nullptr) {
            return nullptr;
        }
        return mChildren.head()->value();
    }

    template <typename T>
    T* AllocatorNode<T>::GetParent() const {
        return mParent;
    }

    template <typename T>
    T* AllocatorNode<T>::AppendChild(std::unique_ptr<T> obj) {
        ASSERT(obj != nullptr);
        obj->mParent = this->value();
        mChildren.Append(obj.release());
        return mChildren.tail()->value();
    }

    template <typename T>
    std::unique_ptr<T> AllocatorNode<T>::RemoveChild(T* ptr) {
        ASSERT(ptr != nullptr);
        ASSERT(ptr->IsInList());
        ptr->RemoveFromList();
        return std::unique_ptr<T>(ptr);
    }

    // Explictly instantiate the template to ensure the compiler has the
    // definition of the require type outside of this file.
    template class AllocatorNode<MemoryAllocator>;

}  // namespace gpgmm
