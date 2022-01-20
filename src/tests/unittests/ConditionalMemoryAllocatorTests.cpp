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

#include "gpgmm/ConditionalMemoryAllocator.h"

#include <memory>

using namespace gpgmm;

class ConditionalMemoryAllocatorTests : public testing::Test {
  public:
    class DummyMemoryAllocator : public MemoryAllocator {
      public:
        void DeallocateMemory(MemoryAllocation* allocation) override {
            return;
        }

        std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t size,
                                                            uint64_t alignment,
                                                            bool neverAllocate) override {
            mStats.UsedMemoryUsage += size;
            return std::make_unique<MemoryAllocation>(/*allocator*/ this, /*memory*/ nullptr);
        }
    };
};

TEST_F(ConditionalMemoryAllocatorTests, Basic) {
    constexpr uint64_t conditionalSize = 16u;
    ConditionalMemoryAllocator alloc(std::make_unique<DummyMemoryAllocator>(),
                                     std::make_unique<DummyMemoryAllocator>(), conditionalSize);

    // Smaller allocation uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.TryAllocateMemory(4, 1);
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->QueryInfo().UsedMemoryUsage, 4u);
    }

    // Equal size allocation uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.TryAllocateMemory(16, 1);
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->QueryInfo().UsedMemoryUsage, 20u);
    }

    // Larger allocation uses secondAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.TryAllocateMemory(24, 1);
        ASSERT_EQ(alloc.GetSecondAllocatorForTesting()->QueryInfo().UsedMemoryUsage, 24u);
    }

    // Smaller allocation again uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.TryAllocateMemory(4, 1);
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->QueryInfo().UsedMemoryUsage, 24u);
    }

    // Larger allocation again uses secondAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.TryAllocateMemory(24, 1);
        ASSERT_EQ(alloc.GetSecondAllocatorForTesting()->QueryInfo().UsedMemoryUsage, 48u);
    }
}
