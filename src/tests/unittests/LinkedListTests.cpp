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

#include "gpgmm/utils/LinkedList.h"

using namespace gpgmm;

// Tests functional additions made to LinkedList.h.
class LinkedListTests : public testing::Test {
  public:
    class FakeObject final : public LinkNode<FakeObject> {
      public:
        FakeObject(size_t id = 0) : mId(id) {
        }

        virtual ~FakeObject() {
            if (IsInList()) {
                RemoveFromList();
            }
        }
        size_t mId = 0;
    };
};

TEST_F(LinkedListTests, Insert) {
    LinkNode<FakeObject>* start = new FakeObject();
    LinkNode<FakeObject>* middle = new FakeObject();
    LinkNode<FakeObject>* end = new FakeObject();

    LinkedList<FakeObject> list;
    list.push_front(middle);
    list.push_front(start);
    list.push_back(end);

    EXPECT_EQ(list.head(), start);
    EXPECT_EQ(list.tail(), end);

    EXPECT_FALSE(list.empty());
    EXPECT_EQ(list.size(), 3u);
}

TEST_F(LinkedListTests, Remove) {
    LinkNode<FakeObject>* start = new FakeObject();
    LinkNode<FakeObject>* middle = new FakeObject();
    LinkNode<FakeObject>* end = new FakeObject();

    LinkedList<FakeObject> list;
    list.push_back(start);
    list.push_back(middle);
    list.push_back(end);

    list.remove(middle);
    list.remove(start);
    list.remove(end);

    EXPECT_TRUE(list.empty());
    EXPECT_EQ(list.size(), 0u);
}

TEST_F(LinkedListTests, Clear) {
    LinkNode<FakeObject>* first = new FakeObject();
    LinkNode<FakeObject>* second = new FakeObject();
    LinkNode<FakeObject>* third = new FakeObject();

    LinkedList<FakeObject> list;
    list.push_back(first);
    list.push_back(second);
    list.push_back(third);

    EXPECT_EQ(list.size(), 3u);

    list.clear();

    EXPECT_TRUE(list.empty());
    EXPECT_EQ(list.size(), 0u);
}

TEST_F(LinkedListTests, Move) {
    LinkNode<FakeObject>* objectInFirstList = new FakeObject();

    LinkedList<FakeObject> firstList;
    firstList.push_back(objectInFirstList);
    EXPECT_EQ(firstList.size(), 1u);
    EXPECT_FALSE(firstList.empty());

    EXPECT_EQ(firstList.head(), objectInFirstList);
    EXPECT_EQ(firstList.tail(), objectInFirstList);

    LinkedList<FakeObject> secondList(std::move(firstList));
    EXPECT_EQ(secondList.size(), 1u);
    EXPECT_FALSE(secondList.empty());

    EXPECT_EQ(secondList.head(), objectInFirstList);
    EXPECT_EQ(secondList.tail(), objectInFirstList);
}

TEST_F(LinkedListTests, Iterator) {
    LinkedList<FakeObject> list;
    list.push_back(new FakeObject(1));
    list.push_back(new FakeObject(2));
    list.push_back(new FakeObject(3));

    // Iterate through the whole range.
    size_t index = 0;
    for (auto& node : list) {
        EXPECT_EQ(node.value()->mId, ++index);
    }

    EXPECT_EQ(index, list.size());

    // Iterate through the whole range again (but using const).
    index = 0;
    for (const auto& node : list) {
        EXPECT_EQ(node.value()->mId, ++index);
    }

    // Iterate through the whole range but remove the first.
    index = 0;
    for (auto& node : list) {
        if (node.value()->mId == 1) {
            list.remove(node.value());
        }
        EXPECT_EQ(node.value()->mId, ++index);
    }

    EXPECT_EQ(index, list.size() + 1);
}
