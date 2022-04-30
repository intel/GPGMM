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

TEST(LinkedListTests, RemoveAndDeleteAll) {
    LinkNode<FakeObject>* first = new FakeObject();
    LinkNode<FakeObject>* second = new FakeObject();
    LinkNode<FakeObject>* third = new FakeObject();

    LinkedList<FakeObject> list;
    list.Append(first);
    list.Append(second);
    list.Append(third);

    list.RemoveAndDeleteAll();
    EXPECT_TRUE(list.empty());
}
