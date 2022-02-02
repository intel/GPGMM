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

#include "gpgmm/common/RefCount.h"

using namespace gpgmm;

class DummyObject : public RefCounted {
  public:
    DummyObject() : RefCounted(0) {
    }
};

TEST(RefCountTests, IncrementDecrement) {
    RefCounted refcount(2);
    EXPECT_FALSE(refcount.Unref());
    EXPECT_EQ(refcount.RefCount(), 1);

    EXPECT_TRUE(refcount.HasOneRef());

    EXPECT_TRUE(refcount.Unref());
    EXPECT_EQ(refcount.RefCount(), 0);

    EXPECT_FALSE(refcount.HasOneRef());
}

TEST(RefCountTests, ScopedRef) {
    ScopedRef<DummyObject> firstRef(new DummyObject());
    EXPECT_EQ(firstRef->RefCount(), 1);

    ScopedRef<DummyObject> secondRef = firstRef;
    EXPECT_EQ(secondRef->RefCount(), 2);

    DummyObject* ptr = firstRef.Detach();
    ASSERT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->RefCount(), 2);

    ScopedRef<DummyObject> firstRefAgain;
    firstRefAgain.Attach(ptr);
    EXPECT_EQ(ptr->RefCount(), 2);

    EXPECT_TRUE(firstRefAgain == secondRef);
    EXPECT_FALSE(firstRef == firstRefAgain);

    ScopedRef<DummyObject> firstRefAgainAquired =
        ScopedRef<DummyObject>::Acquire(firstRefAgain.Detach());
    EXPECT_EQ(firstRefAgainAquired->RefCount(), 2);

    EXPECT_TRUE(firstRefAgainAquired == secondRef);
    EXPECT_FALSE(firstRef == firstRefAgainAquired);

    firstRefAgainAquired = nullptr;
    EXPECT_EQ(secondRef->RefCount(), 1);

    secondRef = nullptr;
    EXPECT_TRUE(secondRef == nullptr);
}
