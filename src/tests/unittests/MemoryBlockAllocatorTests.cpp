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

#include "src/common/Assert.h"
#include "Memory.h"
#include "MemoryBlockAllocator.h"
#include "BuddyAllocator.h"

using namespace gpgmm;

static constexpr uint64_t kHeapSize = 128u;

class DummyMemoryAllocator : public MemoryAllocator {
  public:
    void AllocateMemory(MemoryAllocation& allocation) override {
        AllocationInfo info = {};
        info.mMethod = AllocationMethod::kStandalone;
        allocation = {this, info, /*offset*/ 0, new MemoryBase()};
    }

    void DeallocateMemory(MemoryAllocation& allocation) override {
        ASSERT(allocation.GetInfo().mMethod == gpgmm::AllocationMethod::kStandalone);
        ASSERT(allocation.GetMemory() != nullptr);
        delete allocation.GetMemory();
    }

    void Release() override {
    }

    uint64_t GetMemorySize() const override {
        return kHeapSize;
    }

    uint64_t GetMemoryAlignment() const override {
        return 0;
    }
};

TEST(MemoryBlockAllocatorTests, SingleBlock) {
    DummyMemoryAllocator memoryAllocator;
    BuddyAllocator blockAllocator(kHeapSize);
    MemoryBlockAllocator allocator(&memoryAllocator, &blockAllocator);

    MemoryAllocation allocation;
    allocator.SubAllocate(4, 1, allocation);
    ASSERT_EQ(allocation.GetInfo().mMethod, AllocationMethod::kSubAllocated);

    allocator.DeallocateMemory(allocation);
}