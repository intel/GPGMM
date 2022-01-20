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

#include "gpgmm/MemoryAllocator.h"

using namespace gpgmm;

static uint64_t DestructCount = 0;
static uint64_t ReleaseMemoryCount = 0;

class MemoryAllocatorTests : public testing::Test {
  public:
    void SetUp() override {
        DestructCount = 0;
        ReleaseMemoryCount = 0;
    }

    struct DummyMemoryAllocator : public MemoryAllocator {
        ~DummyMemoryAllocator() override {
            DestructCount++;
        }

        void ReleaseMemory() override {
            MemoryAllocator::ReleaseMemory();
            ReleaseMemoryCount++;
        }

        // MemoryAllocator interface (no-op).
        std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t size,
                                                            uint64_t alignment,
                                                            bool neverAllocate) override {
            return {};
        }

        void DeallocateMemory(MemoryAllocation* allocation) override {
            return;
        }
    };
};

TEST_F(MemoryAllocatorTests, SingleAllocatorNode) {
    auto child = std::make_unique<DummyMemoryAllocator>();
    auto parent = std::make_unique<DummyMemoryAllocator>();

    parent->AppendChild(std::move(child));

    EXPECT_TRUE(parent->HasChild());

    parent->ReleaseMemory();
    EXPECT_EQ(ReleaseMemoryCount, 2u);

    parent.reset();
    EXPECT_EQ(DestructCount, 2u);
}

TEST_F(MemoryAllocatorTests, MultipleAllocatorNodes) {
    auto firstChild = std::make_unique<DummyMemoryAllocator>();
    auto secondChild = std::make_unique<DummyMemoryAllocator>();
    auto thirdChild = std::make_unique<DummyMemoryAllocator>();

    auto parent = std::make_unique<DummyMemoryAllocator>();

    parent->AppendChild(std::move(firstChild));
    parent->AppendChild(std::move(secondChild));
    parent->AppendChild(std::move(thirdChild));

    EXPECT_TRUE(parent->HasChild());

    parent->ReleaseMemory();
    EXPECT_EQ(ReleaseMemoryCount, 4u);

    parent.reset();
    EXPECT_EQ(DestructCount, 4u);
}

TEST_F(MemoryAllocatorTests, HieraticalAllocatorNodes) {
    auto grandChild = std::make_unique<DummyMemoryAllocator>();
    auto child = std::make_unique<DummyMemoryAllocator>();
    auto parent = std::make_unique<DummyMemoryAllocator>();

    child->AppendChild(std::move(grandChild));
    parent->AppendChild(std::move(child));

    EXPECT_TRUE(parent->HasChild());

    parent->ReleaseMemory();
    EXPECT_EQ(ReleaseMemoryCount, 3u);

    parent.reset();
    EXPECT_EQ(DestructCount, 3u);
}
