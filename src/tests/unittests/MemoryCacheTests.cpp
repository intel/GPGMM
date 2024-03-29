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

#include <gtest/gtest.h>

#include "gpgmm/common/MemoryCache.h"

using namespace gpgmm;

struct FakeObject {
    FakeObject(size_t key = 0) : mKey(key) {
    }
    size_t GetKey() const {
        return mKey;
    }
    size_t mKey;
};

// Verify the same object maps to the same entry.
TEST(MemoryCacheTests, SingleEntry) {
    MemoryCache<FakeObject> cache;

    auto firstEntry = cache.GetOrCreate(FakeObject{0}, false);
    ASSERT_NE(firstEntry.Get(), nullptr);
    EXPECT_EQ(firstEntry.Get()->GetRefCount(), 1u);
    EXPECT_EQ(cache.GetStats().NumOfMisses, 1u);
    EXPECT_EQ(cache.GetStats().NumOfHits, 0u);

    auto secondEntry = cache.GetOrCreate(FakeObject{0}, false);
    ASSERT_NE(secondEntry.Get(), nullptr);
    EXPECT_EQ(secondEntry.Get()->GetRefCount(), 2u);
    EXPECT_EQ(cache.GetStats().NumOfMisses, 1u);
    EXPECT_EQ(cache.GetStats().NumOfHits, 1u);

    EXPECT_EQ(firstEntry.Get(), secondEntry.Get());
    EXPECT_EQ(secondEntry.Get()->GetRefCount(), 2u);
    EXPECT_EQ(firstEntry.Get()->GetRefCount(), 2u);
}

// Verify multiple objects maps to seperate entries.
TEST(MemoryCacheTests, MultipleEntries) {
    MemoryCache<FakeObject> cache;

    auto firstEntry = cache.GetOrCreate(FakeObject{1}, false);
    ASSERT_NE(firstEntry.Get(), nullptr);

    auto secondEntry = cache.GetOrCreate(FakeObject{2}, false);
    ASSERT_NE(firstEntry.Get(), nullptr);

    EXPECT_NE(firstEntry.Get(), secondEntry.Get());
    EXPECT_EQ(firstEntry.Get()->GetRefCount(), 1u);
    EXPECT_EQ(secondEntry.Get()->GetRefCount(), 1u);

    auto thirdEntry = cache.GetOrCreate(FakeObject{1}, false);
    ASSERT_NE(thirdEntry.Get(), nullptr);

    auto forthEntry = cache.GetOrCreate(FakeObject{2}, false);
    ASSERT_NE(forthEntry.Get(), nullptr);

    EXPECT_EQ(firstEntry.Get(), thirdEntry.Get());
    EXPECT_EQ(secondEntry.Get(), forthEntry.Get());
    EXPECT_EQ(thirdEntry.Get()->GetRefCount(), 2u);
    EXPECT_EQ(forthEntry.Get()->GetRefCount(), 2u);
}

// Verify entries grow and shrink cache by scope.
TEST(MemoryCacheTests, ShrinkCache) {
    MemoryCache<FakeObject> cache;
    {
        auto entry = cache.GetOrCreate(FakeObject{1}, false);
        EXPECT_EQ(cache.GetSize(), 1u);
    }
    {
        auto entry = cache.GetOrCreate(FakeObject{1}, false);
        EXPECT_EQ(cache.GetSize(), 1u);
    }

    EXPECT_EQ(cache.GetSize(), 0u);

    auto entryOne = cache.GetOrCreate(FakeObject{1}, false);
    auto entryTwo = cache.GetOrCreate(FakeObject{1}, false);
    EXPECT_EQ(entryOne.Get()->GetRefCount(), 2u);
}
