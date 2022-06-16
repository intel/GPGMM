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

#include "gpgmm/common/AllocatorNode.h"

#include "gpgmm/common/MemoryAllocator.h"

namespace gpgmm {

    template <typename T>
    AllocatorNode<T>::AllocatorNode(std::unique_ptr<T> next) : LinkNode<T>() {
        InsertIntoChain(std::move(next));
    }

    template <typename T>
    AllocatorNode<T>::~AllocatorNode() {
        // Deletes adjacent node recursively (post-order).
        if (mNext != nullptr) {
            SafeDelete(mNext);
        }

        if (LinkNode<T>::IsInList()) {
            LinkNode<T>::RemoveFromList();
        }
    }

    template <typename T>
    T* AllocatorNode<T>::GetNextInChain() const {
        return static_cast<T*>(mNext);
    }

    template <typename T>
    T* AllocatorNode<T>::GetParent() const {
        return mParent;
    }

    template <typename T>
    void AllocatorNode<T>::InsertIntoChain(std::unique_ptr<T> next) {
        ASSERT(next != nullptr);
        next->mParent = this->value();
        mNext = next.release();
    }

    // Explictly instantiate the template to ensure the compiler has the
    // definition of the require type outside of this file.
    template class AllocatorNode<MemoryAllocator>;

}  // namespace gpgmm
