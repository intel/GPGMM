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
    start->InsertAfter(list.tail());
    middle->InsertAfter(list.tail());
    end->InsertAfter(list.tail());

    EXPECT_EQ(list.head(), start);
    EXPECT_EQ(list.tail(), end);

    EXPECT_FALSE(list.empty());
}

TEST_F(LinkedListTests, Remove) {
    LinkNode<FakeObject>* start = new FakeObject();
    LinkNode<FakeObject>* middle = new FakeObject();
    LinkNode<FakeObject>* end = new FakeObject();

    LinkedList<FakeObject> list;
    start->InsertAfter(list.tail());
    middle->InsertAfter(list.tail());
    end->InsertAfter(list.tail());

    start->RemoveFromList();
    middle->RemoveFromList();
    end->RemoveFromList();

    EXPECT_TRUE(list.empty());
}

TEST_F(LinkedListTests, Clear) {
    LinkNode<FakeObject>* first = new FakeObject();
    LinkNode<FakeObject>* second = new FakeObject();
    LinkNode<FakeObject>* third = new FakeObject();

    LinkedList<FakeObject> list;
    first->InsertAfter(list.tail());
    second->InsertAfter(list.tail());
    third->InsertAfter(list.tail());

    list.clear();

    EXPECT_TRUE(list.empty());
}

TEST_F(LinkedListTests, Move) {
    LinkNode<FakeObject>* objectInFirstList = new FakeObject();

    LinkedList<FakeObject> firstList;
    objectInFirstList->InsertAfter(firstList.tail());
    EXPECT_FALSE(firstList.empty());

    EXPECT_EQ(firstList.head(), objectInFirstList);
    EXPECT_EQ(firstList.tail(), objectInFirstList);

    LinkedList<FakeObject> secondList(std::move(firstList));
    EXPECT_FALSE(secondList.empty());

    EXPECT_EQ(secondList.head(), objectInFirstList);
    EXPECT_EQ(secondList.tail(), objectInFirstList);
}

TEST_F(LinkedListTests, Iterator) {
    LinkNode<FakeObject>* first = new FakeObject(1);
    LinkNode<FakeObject>* second = new FakeObject(2);
    LinkNode<FakeObject>* third = new FakeObject(3);

    LinkedList<FakeObject> list;
    first->InsertAfter(list.tail());
    second->InsertAfter(list.tail());
    third->InsertAfter(list.tail());

    // Iterate through the whole range.
    size_t index = 0;
    for (auto& node : list) {
        EXPECT_EQ(node.value()->mId, ++index);
    }

    // Iterate through the whole range again (but using const).
    index = 0;
    for (const auto& node : list) {
        EXPECT_EQ(node.value()->mId, ++index);
    }

    // Iterate through the whole range but have the first remove itself.
    index = 0;
    for (auto& node : list) {
        if (node.value()->mId == 1) {
            node.RemoveFromList();
        }
        EXPECT_EQ(node.value()->mId, ++index);
    }
}

TEST_F(LinkedListTests, ListWithSize) {
    LinkNode<FakeObject>* first = new FakeObject(1);
    LinkNode<FakeObject>* second = new FakeObject(2);
    LinkNode<FakeObject>* third = new FakeObject(3);

    SizedLinkedList<FakeObject> list;
    list.push_front(first);
    list.push_front(second);
    list.push_front(third);

    EXPECT_EQ(list.size(), 3u);

    list.pop_front();
    EXPECT_EQ(list.head(), second);
    EXPECT_EQ(list.size(), 2u);

    list.remove(second);
    EXPECT_EQ(list.head(), first);
    EXPECT_EQ(list.size(), 1u);

    list.clear();
    EXPECT_EQ(list.size(), 0u);
}
