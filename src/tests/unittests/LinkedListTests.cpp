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

class FakeObject final : public LinkNode<FakeObject> {
  public:
    virtual ~FakeObject() {
        if (IsInList()) {
            RemoveFromList();
        }
    }
};

TEST(LinkedListTests, Insert) {
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

TEST(LinkedListTests, Remove) {
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

TEST(LinkedListTests, Clear) {
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
