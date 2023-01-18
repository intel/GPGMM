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

#include "gpgmm/d3d12/UnknownD3D12.h"

using namespace gpgmm::d3d12;

class TestUnknownSubClass final : public Unknown {
  public:
    TestUnknownSubClass() {
        mInstanceCount++;
    }
    ~TestUnknownSubClass() override {
        mInstanceCount--;
    }
    static uint32_t mInstanceCount;
};

uint32_t TestUnknownSubClass::mInstanceCount = 0u;

TEST(D3D12UnknownTests, Unknown) {
    EXPECT_EQ(TestUnknownSubClass::mInstanceCount, 0u);

    // Unknown must be acquired/associated since it already
    // refs itself upon creation.
    uint32_t refCount = 0;
    ComPtr<TestUnknownSubClass> unknownObj;
    unknownObj.Attach(new TestUnknownSubClass());

    EXPECT_EQ(TestUnknownSubClass::mInstanceCount, 1u);

    refCount++;

    EXPECT_EQ(unknownObj->AddRef(), ++refCount);
    EXPECT_EQ(unknownObj->AddRef(), ++refCount);

    ComPtr<IDispatch> otherUnknownObj2;
    EXPECT_EQ(E_NOINTERFACE, unknownObj.As(&otherUnknownObj2));

    // ComPtr QI refs |unknownObj|.
    ComPtr<IUnknown> otherUnknownObj;
    EXPECT_EQ(S_OK, unknownObj.As(&otherUnknownObj));
    refCount++;

    EXPECT_EQ(unknownObj->Release(), --refCount);
    EXPECT_EQ(unknownObj->Release(), --refCount);

    otherUnknownObj = nullptr;
    unknownObj = nullptr;

    EXPECT_EQ(TestUnknownSubClass::mInstanceCount, 0u);
}
