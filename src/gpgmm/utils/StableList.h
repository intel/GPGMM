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

#ifndef SRC_GPGMM_UTILS_STABLELIST_H_
#define SRC_GPGMM_UTILS_STABLELIST_H_

#include "Assert.h"
#include "Compiler.h"

#include <array>
#include <memory>
#include <vector>

namespace gpgmm {

    /* StableList is like a STL vector, offering reference stability. StableList is used
    to contain data like a linked-list but is stored using one or more STL vectors (See
    the Q&A section to understand how this differs from std::vector or std::list).

    Insert or remove from the front is O(1), from elsewhere O(N), where random deletion is allowed
    but slower since items will no longer be contiguously allocated. If you need fast random
    insertion, use another data structure.

    To insert items to the list, use push_back or emplace_back:
    \code
    StableList<MyItemT, kSizePerChunk> myList;

    MyItemT myItem = ...;
    myList.push_back(item1); // Or
    myList.emplace_back(...);
    \endcode

    To get the position of the item in the back:
    \code
    auto it = myList.end();
    size_t index = myList.size() - 1;
    \endcode

    To remove any element from the list:
    \code
    myList.erase(index); or // erase(iterator)
    \endcode

    To get number of items in the list:
    \code
    size_t size = myList.occupied_size();
    \endcode

    To iterate through the list:
    \code
    for (auto& it : list) {
      ...
    }
    \endcode

    Questions and Answers:

    Q. When should I use StableList over a linked-list?

    A. The main reason to use StableList over a linked-list is to improve performance by using
    contiguous memory for list-storage. A StableList will almost be always faster to iterate,
    insert, and remove **unless** the majority of items reside in the middle of the list.

    Q. How does StableList implementation differ from std::vector?

    A. StableList is similar to STL vector except it is stable. Stable means pointers or
    references to items are guarenteed to remain valid where removing any element does not
    invalidate others. And unlike a std::vector, the cost of growth is predictable and constant.

    Under the hood, StableList maintains two contigious allocated containers: a "dirty bit" array
    to support random deletion and a normal std::vector to store the data.
    */
    template <typename T, size_t ChunkSize = 1024>
    class StableList {
      public:
        struct Chunk {
            std::vector<T> mData;
            std::array<bool, ChunkSize> mOccupied = {};  // For random deletion.
        };

        StableList() = default;

        // Contructs the container with count default-inserted instances of T.
        explicit StableList(size_t count) {
            for (size_t i = 0; i < count; ++i) {
                emplace_back();
            }
        }

        // Contructs the container with count copies of value |value|.
        StableList(size_t count, const T& value) {
            for (size_t i = 0; i < count; ++i) {
                push_back(value);
            }
        }

        // Removes unused capacity. Reduces capacity() to size().
        //
        // Reduces from the end and only when unoccupied. If the chunk size decreases to zero, the
        // chunk will be removed too.
        void shrink_to_fit() {
            for (size_t i = mChunks.size(); i > 0; i--) {
                auto& chunk = mChunks[i - 1];
                for (size_t j = chunk->mData.size(); j > 0; j--) {
                    if (!chunk->mOccupied[j - 1]) {
                        chunk->mData.pop_back();
                        chunk->mOccupied[j - 1] = false;
                    } else {
                        return;
                    }
                }
                if (chunk->mData.size() == 0) {
                    mChunks.pop_back();
                }
            }
        }

        // Remove item from the back.
        void pop_back() {
            erase(GetSizeWithUnused() - 1);
        }

        // Erase item by index, whose value is flatten or value of size - 1.
        //
        // Erasing from a position other than the end will not erase immediately. Not until
        // no other positions after it are also erased.
        void erase(size_t index) {
            ASSERT(!empty());
            bool* isUsed = &mChunks[index / ChunkSize]->mOccupied[index % ChunkSize];
            if (!*isUsed) {
                return;  // Already erased.
            }

            *isUsed = false;

            // Erasing anywhere other then the end will cause the underlying vector to reallocate
            // and invalidate iterators/references AFTER the point of erase. To prevent this, we
            // shrink the size from the end, using the free bit vector to always keep the last one
            // valid (if not empty).
            shrink_to_fit();

            mSize--;
        }

        // Insert item in back of the list, added at size() position (or before push_back is
        // called).
        void push_back(const T& lvalue) {
            Chunk& chunk = GetOrAddLastChunk();
            chunk.mData.push_back(lvalue);
            chunk.mOccupied[chunk.mData.size() - 1] = true;
            mSize++;
        }

        // Insert item in back of the list, added at size() position (or before push_back is
        // called).
        void push_back(T&& rvalue) {
            Chunk& chunk = GetOrAddLastChunk();
            chunk.mData.push_back(std::move(rvalue));
            chunk.mOccupied[chunk.mData.size() - 1] = true;
            mSize++;
        }

        // Insert item in-place in back of the list.
        template <class... Args>
        void emplace_back(Args&&... args) {
            Chunk& chunk = GetOrAddLastChunk();
            chunk.mData.emplace_back(std::forward<Args>(args)...);
            chunk.mOccupied[chunk.mData.size() - 1] = true;
            mSize++;
        }

        // Get the last item in the list.
        T& back() {
            return mChunks.back()->mData.back();
        }

        // Get the last item in the list.
        const T& back() const {
            return mChunks.back()->mData.back();
        }

        // Get the allocated size or number of chunks allocated x size per chunk.
        size_t capacity() const {
            return mChunks.size() * ChunkSize;
        }

        // Get the occupied size, or size not counting erased items.
        size_t occupied_size() const {
            return mSize;
        }

        // Get the size, counting both occupied and non-occupied items.
        size_t size() const {
            if (empty()) {
                return 0;
            }
            return GetSizeWithUnused();
        }

        // Get the max size of the list.
        size_t max_size() const {
            return std::numeric_limits<size_t>::max();
        }

        // Check if list is empty or the occupied size is zero.
        bool empty() const {
            return occupied_size() == 0;
        }

        // Increase the capacity of the list.
        void reserve(size_t newCapacity) {
            while (capacity() < newCapacity) {
                AddChunk();
            }
        }

        T& operator[](size_t index) {
            return mChunks[index / ChunkSize]->mData[index % ChunkSize];
        }

        const T& operator[](size_t index) const {
            return const_cast<StableList<T, ChunkSize>&>(*this)[index];
        }

        bool operator!=(const StableList<T, ChunkSize>& other) const {
            return !operator==(other);
        }

        bool operator==(const StableList<T, ChunkSize>& other) const {
            return occupied_size() == other.occupied_size() &&
                   std::equal(cbegin(), cend(), other.cbegin());
        }

      private:
        // Holes in the middle of each chunk are not reported by size() but must otherwise be
        // indexed for operations to work (eg. erase, enumeration).
        size_t GetSizeWithUnused() const {
            ASSERT(!empty());
            return (mChunks.size() - 1) * ChunkSize + mChunks.back()->mData.size();
        }

        Chunk& GetOrAddLastChunk() {
            if (GPGMM_UNLIKELY(mChunks.empty() ||
                               mChunks.back()->mData.size() == ChunkSize)) {  // empty or full
                AddChunk();
            }
            return *mChunks.back();
        }

        void AddChunk() {
            auto chunk = std::make_unique<Chunk>();
            // Stability is only guarenteed if there is reallocation and since reallocation is only
            // possible when size == capacity, simply reserve it upfront.
            chunk->mData.reserve(ChunkSize);
            mChunks.push_back(std::move(chunk));
        }

        using storage_type = std::vector<std::unique_ptr<Chunk>>;
        storage_type mChunks;

        size_t mSize = 0;

        template <class StableListT>
        struct StableListIteratorBase {
            StableListIteratorBase(StableListT* list = nullptr, size_t index = 0)
                : mList(list), mIndex(index) {
            }

            T& operator*() const {
                return (*this->mList)[this->mIndex];
            }

            StableListIteratorBase& operator++() {
                mIndex++;
                for (size_t i = mIndex / ChunkSize; i < mList->mChunks.size(); i++) {
                    auto& chunk = mList->mChunks[i];
                    for (size_t j = mIndex % ChunkSize; j < chunk->mData.size(); j++) {
                        if (chunk->mOccupied[j]) {
                            return *this;
                        }
                        mIndex++;
                    }
                }
                return *this;
            }

            bool operator==(const StableListIteratorBase& it) const {
                return mList == it.mList && mIndex == it.mIndex;
            }

            size_t index() const {
                return mIndex;
            }

            StableListT* list() const {
                return mList;
            }

          protected:
            StableListT* mList;
            size_t mIndex;
        };

      public:
        struct iterator : public StableListIteratorBase<StableList<T, ChunkSize>> {
            iterator(StableList<T, ChunkSize>* list, size_t index = 0)
                : StableListIteratorBase<StableList<T, ChunkSize>>(list, index) {
            }

            T& operator*() {
                return (*this->mList)[this->mIndex];
            }

            bool operator==(const iterator& it) const {
                return StableListIteratorBase<StableList<T, ChunkSize>>::operator==(it);
            }

            bool operator!=(const iterator& it) const {
                return !operator==(it);
            }

            iterator& operator++() {
                StableListIteratorBase<StableList<T, ChunkSize>>::operator++();
                return *this;
            }

            iterator& operator+=(const int offset) {
                for (int i = 0; i < offset; i++) {
                    StableListIteratorBase<StableList<T, ChunkSize>>::operator++();
                }
                return *this;
            }

            iterator operator+(int offset) const {
                iterator tmp = *this;
                tmp += offset;
                return tmp;
            }
        };

        struct const_iterator : public StableListIteratorBase<const StableList<T, ChunkSize>> {
            const_iterator(const iterator& it)
                : StableListIteratorBase<const StableList<T, ChunkSize>>(it.list(), it.index()) {
            }

            const_iterator(StableList<T, ChunkSize> const* list, size_t index)
                : StableListIteratorBase<const StableList<T, ChunkSize>>(list, index) {
            }

            const T& operator*() const {
                return (*this->mList)[this->mIndex];
            }

            bool operator==(const const_iterator& it) const {
                return StableListIteratorBase<const StableList<T, ChunkSize>>::operator==(it);
            }

            bool operator!=(const const_iterator& it) const {
                return !operator==(it);
            }

            const_iterator& operator++() {
                StableListIteratorBase<const StableList<T, ChunkSize>>::operator++();
                return *this;
            }

            const_iterator& operator+=(const int offset) {
                for (int i = 0; i < offset; i++) {
                    StableListIteratorBase<StableList<T, ChunkSize>>::operator++();
                }
                return *this;
            }

            const_iterator operator+(int offset) const {
                const_iterator tmp = *this;
                tmp += offset;
                return tmp;
            }
        };

        void erase(const_iterator it) {
            erase(it.index());
        }

        iterator begin() {
            return {this, 0};
        }

        const_iterator begin() const {
            return {this, 0};
        }

        const_iterator cbegin() const {
            return begin();
        }

        iterator end() {
            if (GPGMM_UNLIKELY(empty())) {
                return {this, 0};
            }
            return {this, GetSizeWithUnused()};
        }

        const_iterator end() const {
            if (GPGMM_UNLIKELY(empty())) {
                return {this, 0};
            }
            return {this, GetSizeWithUnused()};
        }

        const_iterator cend() const {
            return end();
        }
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_UTILS_STABLELIST_H_
