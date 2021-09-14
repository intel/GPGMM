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
        void DeallocateMemory(MemoryAllocation* pAllocation) override {
            return;
        }

        void AllocateMemory(uint64_t size,
                            uint64_t alignment,
                            MemoryAllocation** ppAllocation) override {
            mAllocatedBytes += size;
            *ppAllocation = new MemoryAllocation{this, {}, 0, nullptr};
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
        MemoryAllocation* subAllocationPtr = nullptr;
        alloc.AllocateMemory(4, 1, &subAllocationPtr);

        std::unique_ptr<MemoryAllocation> subAllocation(subAllocationPtr);
        ASSERT_EQ(allocA.mAllocatedBytes, 4u);
    }

    // Larger allocation uses allocB.
    {
        MemoryAllocation* subAllocationPtr = nullptr;
        alloc.AllocateMemory(24, 1, &subAllocationPtr);

        std::unique_ptr<MemoryAllocation> subAllocation(subAllocationPtr);
        ASSERT_EQ(allocB.mAllocatedBytes, 24u);
    }

    // Smaller allocation again uses allocA.
    {
        MemoryAllocation* subAllocationPtr = nullptr;
        alloc.AllocateMemory(4, 1, &subAllocationPtr);

        std::unique_ptr<MemoryAllocation> subAllocation(subAllocationPtr);
        ASSERT_EQ(allocA.mAllocatedBytes, 8u);
    }

    // Larger allocation again uses allocB.
    {
        MemoryAllocation* subAllocationPtr = nullptr;
        alloc.AllocateMemory(24, 1, &subAllocationPtr);

        std::unique_ptr<MemoryAllocation> subAllocation(subAllocationPtr);
        ASSERT_EQ(allocB.mAllocatedBytes, 48u);
    }
}
