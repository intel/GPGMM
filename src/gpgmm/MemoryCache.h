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

#ifndef GPGMM_MEMORYCACHE_H_
#define GPGMM_MEMORYCACHE_H_

#include "gpgmm/common/Assert.h"
#include "gpgmm/common/RefCount.h"

#include <unordered_set>

namespace gpgmm {

    // MemoryCache is an associative container that contains a set of unique keys.
    // The primary reason to use MemoryCache over std::unordered_set is because MemoryCache
    // will automatically grow or shrink when entries are no longer referenced. This means the cache
    // size is bounded by the number live entries, eliminating the need for periodic or
    // manual removal of stale keys.
    //
    // To use, you must implement GetKey() for the unique value being stored.
    //
    //   class MyValue {
    //     size_t GetKey() {...}
    //   };
    //
    //   Next, create the cache:
    //
    //   MemoryCache<MyValue> cache;
    //
    //  To add items, use GetOrCreate:
    //
    //  auto entry = cache.GetOrCreate(MyValue(key));
    //
    //  Or remove:
    //
    //  entry = nullptr;
    //
    //  Lastly, to iterate the cache:
    //
    //  for (auto entry : cache) {
    //      MyValue value = entry->GetValue();
    //  }
    //
    template <typename T>
    class MemoryCache;

    template <typename T, typename KeyT = size_t>
    class CacheEntry : public RefCounted {
      public:
        // Constructs entry for lookup.
        explicit CacheEntry(const T& value) : RefCounted(0), mValue(std::move(value)) {
            ASSERT(mCache == nullptr);
        }

        // Constructs entry to store.
        CacheEntry(MemoryCache<T>* cache, const T& value)
            : RefCounted(0), mCache(cache), mValue(std::move(value)) {
            ASSERT(mCache != nullptr);
        }

        ~CacheEntry() {
            if (mCache != nullptr) {  // for lookup or not
                mCache->RemoveCacheEntry(this);
                mCache = nullptr;
            }
            ASSERT(RefCount() == 0);
        }

        T& GetValue() {
            return mValue;
        }

        const T& GetValue() const {
            return mValue;
        }

      private:
        CacheEntry() = delete;

        friend MemoryCache<T>;

        KeyT GetKey() const {
            return mValue.GetKey();
        }

        T&& AcquireValue() {
            return std::move(mValue);
        }

        struct HashFunc {
            KeyT operator()(const CacheEntry<T>* entry) const {
                return entry->GetKey();
            }
        };

        struct EqualityFunc {
            bool operator()(const CacheEntry<T>* a, const CacheEntry<T>* b) const {
                return a->GetKey() == b->GetKey();
            }
        };

        MemoryCache<T>* mCache = nullptr;
        T mValue;
    };

    template <typename T>
    class MemoryCache {
      public:
        using CacheEntryT = CacheEntry<T>;

        using Cache = std::unordered_set<CacheEntryT*,
                                         typename CacheEntryT::HashFunc,
                                         typename CacheEntryT::EqualityFunc>;

        typedef typename Cache::iterator iterator;
        typedef typename Cache::const_iterator const_iterator;

        MemoryCache() = default;

        ~MemoryCache() {
            RemoveAndDeleteAll();
            ASSERT(GetSize() == 0);
        }

        // Inserts |value| into a cache. The |value| may be kept alive until the cache destructs
        // when |keepAlive| is true.
        ScopedRef<CacheEntryT> GetOrCreate(const T& value, bool keepAlive) {
            CacheEntryT tmp(std::move(value));
            const auto& iter = mCache.find(&tmp);
            if (iter != mCache.end()) {
                return (*iter);
            }
            CacheEntryT* entry = new CacheEntryT(this, tmp.AcquireValue());
            if (keepAlive) {
                entry->Ref();
            }
            const bool success = mCache.insert(entry).second;
            ASSERT(success);
            return ScopedRef<CacheEntryT>(entry);
        }

        // Return number of entries.
        size_t GetSize() const {
            return mCache.size();
        }

        // Forward iterator interfaces.
        iterator begin() const {
            return mCache.begin();
        }

        iterator end() const {
            return mCache.end();
        }

        const_iterator cbegin() const {
            return mCache.cbegin();
        }

        const_iterator cend() const {
            return mCache.cend();
        }

        void RemoveAndDeleteAll() {
            for (auto it = mCache.begin(); it != mCache.end();) {
                if ((*it)->Unref()) {
                    auto curr = it;
                    it++;
                    RemoveCacheEntry(*curr);
                } else {
                    it++;
                }
            }
        }

      private:
        friend CacheEntryT;

        void RemoveCacheEntry(CacheEntryT* entry) {
            ASSERT(entry != nullptr);
            ASSERT(entry->RefCount() == 0);
            const size_t removedCount = mCache.erase(entry);
            ASSERT(removedCount == 1);
        }

        Cache mCache;
    };
}  // namespace gpgmm

#endif  // GPGMM_MEMORYCACHE_H_
