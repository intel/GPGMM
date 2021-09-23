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

#include <memory>

#include "src/ConditionalMemoryAllocator.h"

using namespace gpgmm;

class ConditionalMemoryAllocatorTests : public testing::Test {
  public:
    class DummyMemoryAllocator : public MemoryAllocator {
      public:
        void DeallocateMemory(MemoryAllocation* allocation) override {
            return;
        }

        std::unique_ptr<MemoryAllocation> AllocateMemory(uint64_t size,
                                                         uint64_t alignment) override {
            mAllocatedBytes += size;
            AllocationInfo info = {};
            return std::make_unique<MemoryAllocation>(/*allocator*/ this, info, 0, nullptr);
        }

        uint64_t mAllocatedBytes = 0;
    };
};

TEST_F(ConditionalMemoryAllocatorTests, Basic) {
    DummyMemoryAllocator allocA;
    DummyMemoryAllocator allocB;

    constexpr uint64_t conditionalSize = 16u;
    ConditionalMemoryAllocator alloc(&allocA, &allocB, conditionalSize);

    // Smaller allocation uses allocA.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.AllocateMemory(4, 1);
        ASSERT_EQ(allocA.mAllocatedBytes, 4u);
    }

    // Larger allocation uses allocB.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.AllocateMemory(24, 1);
        ASSERT_EQ(allocB.mAllocatedBytes, 24u);
    }

    // Smaller allocation again uses allocA.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.AllocateMemory(4, 1);
        ASSERT_EQ(allocA.mAllocatedBytes, 8u);
    }

    // Larger allocation again uses allocB.
    {
        std::unique_ptr<MemoryAllocation> allocation = alloc.AllocateMemory(24, 1);
        ASSERT_EQ(allocB.mAllocatedBytes, 48u);
    }
}
