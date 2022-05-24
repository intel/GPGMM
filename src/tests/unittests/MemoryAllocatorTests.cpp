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

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/SlabMemoryAllocator.h"
#include "gpgmm/utils/Math.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

static uint64_t DestructCount = 0;
static uint64_t ReleaseMemoryCount = 0;

class TestMemoryAllocator final : public DummyMemoryAllocator {
  public:
    TestMemoryAllocator() = default;

    explicit TestMemoryAllocator(std::unique_ptr<MemoryAllocator> next)
        : DummyMemoryAllocator(std::move(next)) {
    }

    ~TestMemoryAllocator() override {
        DestructCount++;
    }

    uint64_t ReleaseMemory(uint64_t bytesToRelease = kInvalidSize) override {
        ReleaseMemoryCount++;
        return MemoryAllocator::ReleaseMemory(bytesToRelease);
    }
};

class MemoryAllocatorTests : public testing::Test {
  public:
    void SetUp() override {
        DestructCount = 0;
        ReleaseMemoryCount = 0;
    }
};

TEST_F(MemoryAllocatorTests, SingleAllocator) {
    auto child = std::make_unique<TestMemoryAllocator>();
    auto parent = std::make_unique<TestMemoryAllocator>(std::move(child));

    EXPECT_TRUE(parent->GetNextInChain() != nullptr);

    parent->ReleaseMemory();
    EXPECT_EQ(ReleaseMemoryCount, 2u);

    parent.reset();
    EXPECT_EQ(DestructCount, 2u);
}

TEST_F(MemoryAllocatorTests, MultipleAllocators) {
    auto grandChild = std::make_unique<TestMemoryAllocator>();
    auto child = std::make_unique<TestMemoryAllocator>(std::move(grandChild));
    auto parent = std::make_unique<TestMemoryAllocator>(std::move(child));

    EXPECT_TRUE(parent->GetNextInChain() != nullptr);

    parent->ReleaseMemory();
    EXPECT_EQ(ReleaseMemoryCount, 3u);

    parent.reset();
    EXPECT_EQ(DestructCount, 3u);
}
