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

#include <gtest/gtest.h>

#include "gpgmm/MemoryCache.h"

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

    auto firstEntry = cache.GetOrCreate(FakeObject{0});
    ASSERT_NE(firstEntry.Get(), nullptr);
    EXPECT_EQ(firstEntry.Get()->RefCount(), 1);

    auto secondEntry = cache.GetOrCreate(FakeObject{0});
    ASSERT_NE(secondEntry.Get(), nullptr);
    EXPECT_EQ(secondEntry.Get()->RefCount(), 2);

    EXPECT_EQ(firstEntry.Get(), secondEntry.Get());
    EXPECT_EQ(secondEntry.Get()->RefCount(), 2);
    EXPECT_EQ(firstEntry.Get()->RefCount(), 2);
}

// Verify multiple objects maps to seperate entries.
TEST(MemoryCacheTests, MultipleEntries) {
    MemoryCache<FakeObject> cache;

    auto firstEntry = cache.GetOrCreate(FakeObject{1});
    ASSERT_NE(firstEntry.Get(), nullptr);

    auto secondEntry = cache.GetOrCreate(FakeObject{2});
    ASSERT_NE(firstEntry.Get(), nullptr);

    EXPECT_NE(firstEntry.Get(), secondEntry.Get());
    EXPECT_EQ(firstEntry.Get()->RefCount(), 1);
    EXPECT_EQ(secondEntry.Get()->RefCount(), 1);

    auto thirdEntry = cache.GetOrCreate(FakeObject{1});
    ASSERT_NE(thirdEntry.Get(), nullptr);

    auto forthEntry = cache.GetOrCreate(FakeObject{2});
    ASSERT_NE(forthEntry.Get(), nullptr);

    EXPECT_EQ(firstEntry.Get(), thirdEntry.Get());
    EXPECT_EQ(secondEntry.Get(), forthEntry.Get());
    EXPECT_EQ(thirdEntry.Get()->RefCount(), 2);
    EXPECT_EQ(forthEntry.Get()->RefCount(), 2);
}

// Verify entries grow and shrink cache by scope.
TEST(MemoryCacheTests, ShrinkCache) {
    MemoryCache<FakeObject> cache;
    {
        auto entry = cache.GetOrCreate(FakeObject{1});
        EXPECT_EQ(cache.GetSize(), 1u);
    }
    {
        auto entry = cache.GetOrCreate(FakeObject{1});
        EXPECT_EQ(cache.GetSize(), 1u);
    }

    EXPECT_EQ(cache.GetSize(), 0u);

    auto entryOne = cache.GetOrCreate(FakeObject{1});
    auto entryTwo = cache.GetOrCreate(FakeObject{1});
    EXPECT_EQ(entryOne.Get()->RefCount(), 2);
}
