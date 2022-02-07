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

#include "gpgmm/BuddyMemoryAllocator.h"
#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/SlabMemoryAllocator.h"
#include "gpgmm/common/Math.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

static constexpr uint64_t kDefaultMemorySize = 128u;
static constexpr uint64_t kDefaultMemoryAlignment = 1u;

static uint64_t DestructCount = 0;
static uint64_t ReleaseMemoryCount = 0;

class TestMemoryAllocator : public DummyMemoryAllocator {
  public:
    ~TestMemoryAllocator() override {
        DestructCount++;
    }

    void ReleaseMemory() override {
        MemoryAllocator::ReleaseMemory();
        ReleaseMemoryCount++;
    }

    TestMemoryAllocator* AppendChild(std::unique_ptr<TestMemoryAllocator> obj) {
        return static_cast<TestMemoryAllocator*>(MemoryAllocator::AppendChild(std::move(obj)));
    }

    bool HasChild() const {
        return MemoryAllocator::HasChild();
    }
};

class MemoryAllocatorTests : public testing::Test {
  public:
    void SetUp() override {
        DestructCount = 0;
        ReleaseMemoryCount = 0;
    }
};

TEST_F(MemoryAllocatorTests, SingleAllocatorNode) {
    auto child = std::make_unique<TestMemoryAllocator>();
    auto parent = std::make_unique<TestMemoryAllocator>();

    parent->AppendChild(std::move(child));

    EXPECT_TRUE(parent->HasChild());

    parent->ReleaseMemory();
    EXPECT_EQ(ReleaseMemoryCount, 2u);

    parent.reset();
    EXPECT_EQ(DestructCount, 2u);
}

TEST_F(MemoryAllocatorTests, MultipleAllocatorNodes) {
    auto firstChild = std::make_unique<TestMemoryAllocator>();
    auto secondChild = std::make_unique<TestMemoryAllocator>();
    auto thirdChild = std::make_unique<TestMemoryAllocator>();

    auto parent = std::make_unique<TestMemoryAllocator>();

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
    auto grandChild = std::make_unique<TestMemoryAllocator>();
    auto child = std::make_unique<TestMemoryAllocator>();
    auto parent = std::make_unique<TestMemoryAllocator>();

    child->AppendChild(std::move(grandChild));
    parent->AppendChild(std::move(child));

    EXPECT_TRUE(parent->HasChild());

    parent->ReleaseMemory();
    EXPECT_EQ(ReleaseMemoryCount, 3u);

    parent.reset();
    EXPECT_EQ(DestructCount, 3u);
}

TEST_F(MemoryAllocatorTests, SlabBuddyAllocator) {
    // 1. Create a buddy allocator as the back-end allocator.
    constexpr uint64_t maxBlockSize = 256;
    std::unique_ptr<BuddyMemoryAllocator> buddyAllocator = std::make_unique<BuddyMemoryAllocator>(
        maxBlockSize, kDefaultMemorySize, kDefaultMemoryAlignment,
        std::make_unique<DummyMemoryAllocator>());

    // 2. Create a slab allocator as the front-end allocator.
    constexpr uint64_t kMinBlockSize = 4;
    constexpr uint64_t kMaxSlabSize = maxBlockSize;
    constexpr uint64_t kSlabSize = kDefaultMemorySize / 8;
    SlabCacheAllocator allocator(kMinBlockSize, kMaxSlabSize, kSlabSize, kDefaultMemoryAlignment,
                                 std::move(buddyAllocator));

    // Verify a single slab-buddy sub-allocation.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator.TryAllocateMemory(kMinBlockSize, 1, false);
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetOffset(), 0u);
        EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(allocation->GetSize(), kMinBlockSize);

        allocator.DeallocateMemory(allocation.release());
    }

    // Verify multiple slab-buddy sub-allocation in the same slab are allocated contigiously.
    {
        constexpr uint64_t allocationSize = kMinBlockSize * 2;
        std::unique_ptr<MemoryAllocation> firstAllocation =
            allocator.TryAllocateMemory(allocationSize, 1, false);
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetOffset(), 0u);
        EXPECT_EQ(firstAllocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(firstAllocation->GetSize(), allocationSize);

        EXPECT_EQ(firstAllocation->GetMemory()->GetSize(), kDefaultMemorySize);

        std::unique_ptr<MemoryAllocation> secondAllocation =
            allocator.TryAllocateMemory(allocationSize, 1, false);
        ASSERT_NE(secondAllocation, nullptr);
        EXPECT_EQ(secondAllocation->GetOffset(), allocationSize);
        EXPECT_EQ(secondAllocation->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(secondAllocation->GetSize(), allocationSize);

        EXPECT_EQ(secondAllocation->GetMemory()->GetSize(), kDefaultMemorySize);

        allocator.DeallocateMemory(firstAllocation.release());
        allocator.DeallocateMemory(secondAllocation.release());
    }

    // Verify multiple slab-buddy sub-allocations across buddies are allocated non-contigiously.
    {
        // Fill the first buddy up with slabs.
        std::vector<std::unique_ptr<MemoryAllocation>> allocations = {};
        for (uint32_t i = 0; i < kDefaultMemorySize / kSlabSize; i++) {
            std::unique_ptr<MemoryAllocation> allocation =
                allocator.TryAllocateMemory(kSlabSize, 1, false);
            ASSERT_NE(allocation, nullptr);
            EXPECT_EQ(allocation->GetOffset(), i * kSlabSize);
            EXPECT_EQ(allocation->GetMethod(), AllocationMethod::kSubAllocated);
            EXPECT_GE(allocation->GetSize(), kSlabSize);
            allocations.push_back(std::move(allocation));
        }

        // Next slab-buddy sub-allocation must be in the second buddy.
        std::unique_ptr<MemoryAllocation> firstSlabInSecondBuddy =
            allocator.TryAllocateMemory(kSlabSize, 1, false);
        ASSERT_NE(firstSlabInSecondBuddy, nullptr);
        EXPECT_EQ(firstSlabInSecondBuddy->GetOffset(), 0u);
        EXPECT_EQ(firstSlabInSecondBuddy->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(firstSlabInSecondBuddy->GetSize(), kSlabSize);

        std::unique_ptr<MemoryAllocation> secondSlabInSecondBuddy =
            allocator.TryAllocateMemory(kSlabSize, 1, false);
        ASSERT_NE(secondSlabInSecondBuddy, nullptr);
        EXPECT_EQ(secondSlabInSecondBuddy->GetOffset(), kSlabSize);
        EXPECT_EQ(secondSlabInSecondBuddy->GetMethod(), AllocationMethod::kSubAllocated);
        EXPECT_GE(secondSlabInSecondBuddy->GetSize(), kSlabSize);

        // Free slab in second buddy.
        allocator.DeallocateMemory(secondSlabInSecondBuddy.release());
        allocator.DeallocateMemory(firstSlabInSecondBuddy.release());

        // Free slabs in first buddy.
        for (auto& allocation : allocations) {
            allocator.DeallocateMemory(allocation.release());
        }
    }
}
