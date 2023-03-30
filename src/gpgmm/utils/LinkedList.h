// Copyright 2020 The Dawn Authors
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

#ifndef GPGMM_UTILS_LINKED_LIST_H
#define GPGMM_UTILS_LINKED_LIST_H

#include "Assert.h"
#include "Utils.h"

#include <utility>

namespace gpgmm {

    // Simple LinkedList type. (See the Q&A section to understand how this
    // differs from std::list).
    //
    // To use, start by declaring the class which will be contained in the linked
    // list, as extending LinkNode (this gives it next/previous pointers).
    //
    //   class MyNodeType : public LinkNode<MyNodeType> {
    //     ...
    //   };
    //
    // Next, to keep track of the list's head/tail, use a LinkedList instance:
    //
    //   LinkedList<MyNodeType> list;
    //
    // To add elements to the list, use any of LinkedList::Append,
    // LinkNode::InsertBefore, or LinkNode::InsertAfter:
    //
    //   LinkNode<MyNodeType>* n1 = ...;
    //   LinkNode<MyNodeType>* n2 = ...;
    //   LinkNode<MyNodeType>* n3 = ...;
    //
    //   list.Append(n1);
    //   list.Append(n3);
    //   n3->InsertBefore(n3);
    //
    // Lastly, to iterate through the linked list forwards:
    //
    //   for (LinkNode<MyNodeType>* node = list.head();
    //        node != list.end();
    //        node = node->next()) {
    //     MyNodeType* value = node->value();
    //     ...
    //   }
    //
    // Or to iterate the linked list backwards:
    //
    //   for (LinkNode<MyNodeType>* node = list.tail();
    //        node != list.end();
    //        node = node->previous()) {
    //     MyNodeType* value = node->value();
    //     ...
    //   }
    //
    // Questions and Answers:
    //
    // Q. Should I use std::list or base::LinkedList?
    //
    // A. The main reason to use base::LinkedList over std::list is
    //    performance. If you don't care about the performance differences
    //    then use an STL container, as it makes for better code readability.
    //
    //    Comparing the performance of base::LinkedList<T> to std::list<T*>:
    //
    //    * Erasing an element of type T* from base::LinkedList<T> is
    //      an O(1) operation. Whereas for std::list<T*> it is O(n).
    //      That is because with std::list<T*> you must obtain an
    //      iterator to the T* element before you can call erase(iterator).
    //
    //    * Insertion operations with base::LinkedList<T> never require
    //      heap allocations.
    //
    // Q. How does base::LinkedList implementation differ from std::list?
    //
    // A. Doubly-linked lists are made up of nodes that contain "next" and
    //    "previous" pointers that reference other nodes in the list.
    //
    //    With base::LinkedList<T>, the type being inserted already reserves
    //    space for the "next" and "previous" pointers (base::LinkNode<T>*).
    //    Whereas with std::list<T> the type can be anything, so the implementation
    //    needs to glue on the "next" and "previous" pointers using
    //    some internal node type.

    template <typename T>
    class LinkNode {
      public:
        LinkNode() : previous_(nullptr), next_(nullptr) {
        }
        LinkNode(LinkNode<T>* previous, LinkNode<T>* next) : previous_(previous), next_(next) {
        }

        LinkNode(LinkNode<T>&& rhs) {
            next_ = rhs.next_;
            rhs.next_ = nullptr;
            previous_ = rhs.previous_;
            rhs.previous_ = nullptr;

            // If the node belongs to a list, next_ and previous_ are both non-null.
            // Otherwise, they are both null.
            if (next_) {
                next_->previous_ = this;
                previous_->next_ = this;
            }
        }

        LinkNode& operator=(LinkNode<T>&& rhs) {
            if (this == &rhs) {
                return *this;
            }

            next_ = rhs.next_;
            rhs.next_ = nullptr;
            previous_ = rhs.previous_;
            rhs.previous_ = nullptr;

            // If the node belongs to a list, next_ and previous_ are both non-null.
            // Otherwise, they are both null.
            if (next_) {
                next_->previous_ = this;
                previous_->next_ = this;
            }

            return *this;
        }

        // Insert |this| into the linked list, before |e|.
        void InsertBefore(LinkNode<T>* e) {
            this->next_ = e;
            this->previous_ = e->previous_;
            e->previous_->next_ = this;
            e->previous_ = this;
        }

        // Insert |this| into the linked list, after |e|.
        void InsertAfter(LinkNode<T>* e) {
            this->next_ = e->next_;
            this->previous_ = e;
            e->next_->previous_ = this;
            e->next_ = this;
        }

        // Check if |this| is in a list.
        bool IsInList() const {
            ASSERT((this->previous_ == nullptr) == (this->next_ == nullptr));
            return this->next_ != nullptr;
        }

        // Remove |this| from the linked list.
        void RemoveFromList() {
            this->previous_->next_ = this->next_;
            this->next_->previous_ = this->previous_;
            // next() and previous() return non-null if and only this node is not in any
            // list.
            this->next_ = nullptr;
            this->previous_ = nullptr;
        }

        LinkNode<T>* previous() const {
            return previous_;
        }

        LinkNode<T>* next() const {
            return next_;
        }

        // Cast from the node-type to the value type.
        const T* value() const {
            return static_cast<const T*>(this);
        }

        T* value() {
            return static_cast<T*>(this);
        }

      private:
        LinkNode<T>* previous_;
        LinkNode<T>* next_;
    };

    template <typename LinkNodeT>
    class LinkedListIterator {
      public:
        // Properties required to use iterator with STL (ex. std::distance).
        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = LinkNodeT;
        using pointer = LinkNodeT*;
        using reference = LinkNodeT&;

        LinkedListIterator(LinkNodeT* nodePtr) : mCurrent(nodePtr), mNext(nodePtr->next()) {
        }

        LinkNodeT& operator*() const {
            return *mCurrent;
        }

        LinkNodeT* operator->() {
            return mCurrent;
        }

        LinkedListIterator& operator++() {
            // Keep ahead by one so if the current node is removed from the list, the iterator can
            // still advance to the next node in the list.
            mCurrent = mNext;
            mNext = mNext->next();
            return *this;
        }

        friend bool operator==(const LinkedListIterator& a, const LinkedListIterator& b) {
            return a.mCurrent == b.mCurrent;
        }

        friend bool operator!=(const LinkedListIterator& a, const LinkedListIterator& b) {
            return a.mCurrent != b.mCurrent;
        }

      private:
        LinkNodeT* mCurrent;
        LinkNodeT* mNext;
    };

    template <typename T>
    class LinkedList {
      public:
        using iterator = LinkedListIterator<LinkNode<T>>;
        using const_iterator = LinkedListIterator<LinkNode<T> const>;

        // The "root" node is self-referential, and forms the basis of a circular
        // list (root_.next() will point back to the start of the list,
        // and root_->previous() wraps around to the end of the list).
        LinkedList() : root_(&root_, &root_) {
        }

        ~LinkedList() {
            // If any LinkNodes still exist in the LinkedList, there will be outstanding references
            // to root_ even after it has been freed. We should remove root_ from the list to
            // prevent any future access.
            if (root_.IsInList()) {
                root_.RemoveFromList();
            }
        }

        // Using LinkedList in std::vector or STL container requires the move constructor to not
        // throw.
        LinkedList(LinkedList&& other) noexcept : root_(std::move(other.root_)) {
        }

        LinkedList& operator=(LinkedList&& rhs) {
            if (this != &rhs) {
                root_ = std::move(rhs.root_);
            }
            return *this;
        }

        LinkNode<T>* head() const {
            return root_.next();
        }

        LinkNode<T>* tail() const {
            return root_.previous();
        }

        bool empty() const {
            return head() == end();
        }

        // Empty the list by deleting all nodes.
        // ~T must check if IsInList and call RemoveFromList to unlink itself or clear
        // will ASSERT to indicate programmer error.
        void clear() {
            iterator curr = begin();
            while (curr != end()) {
                curr = erase(curr);
            }
            ASSERT(empty());
        }

        iterator erase(iterator i) {
            SafeDelete(i->value());
            return ++i;
        }

        iterator begin() {
            return iterator(head());
        }

        iterator end() {
            return iterator(&root_);
        }

        const_iterator begin() const {
            return const_iterator(head());
        }

        const_iterator end() const {
            return const_iterator(&root_);
        }

      private:
        LinkNode<T> root_;
    };

}  // namespace gpgmm

#endif  // GPGMM_UTILS_LINKED_LIST_H
