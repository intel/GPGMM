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

#include "gpgmm/common/ConditionalMemoryAllocator.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

TEST(ConditionalMemoryAllocatorTests, Basic) {
    constexpr uint64_t conditionalSize = 16u;
    ConditionalMemoryAllocator alloc(std::make_unique<DummyMemoryAllocator>(),
                                     std::make_unique<DummyMemoryAllocator>(), conditionalSize);

    // Smaller allocation uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(4, 1, false, false, false);
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->GetInfo().UsedMemoryUsage, 4u);
    }

    // Equal size allocation uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(16, 1, false, false, false);
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->GetInfo().UsedMemoryUsage, 20u);
    }

    // Larger allocation uses secondAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(24, 1, false, false, false);
        ASSERT_EQ(alloc.GetSecondAllocatorForTesting()->GetInfo().UsedMemoryUsage, 24u);
    }

    // Smaller allocation again uses firstAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(4, 1, false, false, false);
        ASSERT_EQ(alloc.GetFirstAllocatorForTesting()->GetInfo().UsedMemoryUsage, 24u);
    }

    // Larger allocation again uses secondAllocator.
    {
        std::unique_ptr<MemoryAllocation> allocation =
            alloc.TryAllocateMemory(24, 1, false, false, false);
        ASSERT_EQ(alloc.GetSecondAllocatorForTesting()->GetInfo().UsedMemoryUsage, 48u);
    }
}
