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

#include "gpgmm/utils/StableList.h"

using namespace gpgmm;

TEST(StableListTests, Create) {
    {
        StableList<int, 1024> list(4096);
        EXPECT_EQ(list.occupied_size(), 4096u);
    }

    {
        StableList<int, 1024> list(4096, 0xdeadbeef);
        EXPECT_EQ(list.occupied_size(), 4096u);
    }
}

TEST(StableListTests, Reserve) {
    StableList<int, 1024> list;

    // Reserve exactly the chunk size.
    list.reserve(1024);
    EXPECT_EQ(list.capacity(), 1024u);

    // One over rounds up to nearest chunk.
    list.reserve(1025);
    EXPECT_EQ(list.capacity(), 2048u);
}

TEST(StableListTests, Append) {
    StableList<int, 2> list;
    list.push_back(0);
    list.push_back(1);

    EXPECT_EQ(list.capacity(), 2u);
    EXPECT_EQ(list.occupied_size(), 2u);

    list.push_back(3);
    list.push_back(4);

    EXPECT_EQ(list.capacity(), 4u);
    EXPECT_EQ(list.occupied_size(), 4u);
}

TEST(StableListTests, Insert) {
    StableList<int, 2> list;
    list.push_back(0);
    list.push_back(1);
    list.push_back(2);

    list[0] = 2;
    list[1] = 1;
    list[2] = 0;

    EXPECT_EQ(list[0], 2);
    EXPECT_EQ(list[1], 1);
    EXPECT_EQ(list[2], 0);
}

TEST(StableListTests, RemoveEnds) {
    StableList<int> list;
    list.push_back(0);
    list.push_back(1);
    list.push_back(2);

    EXPECT_EQ(list.occupied_size(), 3u);

    list.pop_back();
    list.pop_back();
    list.pop_back();

    EXPECT_EQ(list.occupied_size(), 0u);
}

TEST(StableListTests, RemoveSame) {
    StableList<int> list;
    list.push_back(0);
    list.push_back(1);

    list.erase(0);
    list.erase(0);  // No-op!

    EXPECT_EQ(list.occupied_size(), 1u);
}

TEST(StableListTests, RemoveMiddle) {
    // Before = []
    // After = [0,1,2,3,4]
    StableList<int, 3> list;
    list.push_back(0);
    list.push_back(1);
    list.push_back(2);
    list.push_back(3);
    list.push_back(4);

    // Before = [0,1,2,3,4]
    // After = [0,_,2,_,4]
    list.erase(1);  // Middle of chunk#1
    list.erase(3);  // Middle of chunk#2

    // Before = [0,_,2,_,4]
    // After = [0,_,2]
    list.pop_back();
    EXPECT_EQ(list.back(), 2);

    // Before = [0,_,2]
    // After = [0,]
    list.pop_back();
    EXPECT_EQ(list.back(), 0);
}

TEST(StableListTests, StableItems) {
    std::vector<int*> ptrs = {};
    StableList<int, 128> list;
    for (size_t i = 0; i < 2048; i++) {
        list.push_back(i);
        ptrs.push_back(&list[i]);
    }

    for (size_t i = 0; i < list.occupied_size(); i++) {
        EXPECT_EQ(*ptrs[i], list[i]);
    }

    // Discard last half.
    for (size_t i = 0; i < list.occupied_size() / 2; i++) {
        list.pop_back();
        ptrs.pop_back();
    }

    for (size_t i = 0; i < list.occupied_size(); i++) {
        EXPECT_EQ(*ptrs[i], list[i]);
    }
}

TEST(StableListTests, Enumerate) {
    // Over a single item in a chunk.
    {
        StableList<int, 4> list;
        list.push_back(0);

        int i = 0;
        for (auto& it : list) {
            EXPECT_EQ(it, i++);
        }

        EXPECT_EQ(i, 1);
    }

    // Over multiple items in a chunk.
    {
        StableList<int, 4> list;
        list.push_back(0);
        list.push_back(1);
        list.push_back(2);
        list.push_back(3);

        int i = 0;
        for (auto& it : list) {
            EXPECT_EQ(it, i++);
        }

        EXPECT_EQ(i, 4);
    }

    // Over multiple chunks.
    {
        StableList<int, 2> list;
        list.push_back(0);
        list.push_back(1);
        list.push_back(2);
        list.push_back(3);
        list.push_back(4);

        int i = 0;
        for (auto& it : list) {
            EXPECT_EQ(it, i++);
        }

        EXPECT_EQ(i, 5);
    }

    // Over holes in odd indexes.
    {
        StableList<int, 2> list;
        list.push_back(0);
        list.push_back(0xdeadbeef);
        list.push_back(2);
        list.push_back(0xdeadbeef);
        list.push_back(4);

        list.erase(1);
        list.erase(3);

        int i = 0;
        int n = 0;
        for (auto& it : list) {
            EXPECT_EQ(it, i);
            i += 2;
            n++;
        }

        EXPECT_EQ(n, 3);
    }

    // Over holes of various sizes.
    {
        StableList<int, 2> list;
        list.push_back(0);
        list.push_back(0xdeadbeef);
        list.push_back(2);
        list.push_back(3);
        list.push_back(0xdeadbeef);
        list.push_back(0xdeadbeef);
        list.push_back(6);
        list.push_back(7);
        list.push_back(8);

        list.erase(1);
        list.erase(4);
        list.erase(5);

        int i = 0;
        int n = 0;
        for (auto& it : list) {
            if (i != 1 && i != 4 && i != 5) {
                EXPECT_EQ(it, i++);
            }
            n++;
        }

        EXPECT_EQ(n, 6);
    }

    // Over empty list.
    {
        StableList<int, 4> list;
        list.push_back(0xdeadbeef);
        list.push_back(0xdeadbeef);

        list.erase(0);
        list.erase(1);

        int i = 0;
        for (auto& _ : list) {
            ASSERT_TRUE(_);
        }
        EXPECT_EQ(i, 0);
    }
}
