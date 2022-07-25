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

#include <array>
#include "gpgmm/utils/ContiguousLinkNodeAllocator.h"
#include "gpgmm/utils/LinkedList.h"

using namespace gpgmm;

std::array<size_t, 4> kObjectsPerBlock = {1, 8, 512, 1000};
uint64_t kTestValue = 0xFFFFFFFF;

class Uint64LinkNode : LinkNode<uint64_t> {
  public:
    explicit Uint64LinkNode(uint64_t value) : mValue(value) {
    }
    uint64_t GetValue() const {
        return mValue;
    }

  private:
    uint64_t mValue;
};

// Ensure a simple allocation succeeds.
TEST(ContiguousLinkNodeAllocatorTests, BasicAllocation) {
    // Test with a uint64_t
    for (size_t objectsPerBlock : kObjectsPerBlock) {
        ContiguousLinkNodeAllocator<uint64_t> allocator(objectsPerBlock);
        uint64_t* pointer = new (allocator.Allocate()) uint64_t(kTestValue);
        ASSERT_EQ(*pointer, kTestValue);
    }

    // Test with a LinkNode
    for (size_t objectsPerBlock : kObjectsPerBlock) {
        ContiguousLinkNodeAllocator<Uint64LinkNode> allocator(objectsPerBlock);
        Uint64LinkNode* pointer = new (allocator.Allocate()) Uint64LinkNode(kTestValue);
        ASSERT_EQ(pointer->GetValue(), kTestValue);
    }
}

// Ensure allocation works when we the number of allocations exceeds the number of allocations per
// block.
TEST(ContiguousLinkNodeAllocatorTests, AllocateInSecondBlock) {
    // Test with a uint64_t
    for (size_t objectsPerBlock : kObjectsPerBlock) {
        ContiguousLinkNodeAllocator<uint64_t> allocator(objectsPerBlock);
        for (uint64_t i = 0; i < objectsPerBlock; i++) {
            allocator.Allocate();
        }

        uint64_t* pointer = new (allocator.Allocate()) uint64_t(kTestValue);
        ASSERT_EQ(*pointer, kTestValue);
    }

    // Test with a LinkNode
    for (size_t objectsPerBlock : kObjectsPerBlock) {
        ContiguousLinkNodeAllocator<Uint64LinkNode> allocator(objectsPerBlock);
        for (uint64_t i = 0; i < objectsPerBlock; i++) {
            allocator.Allocate();
        }

        Uint64LinkNode* pointer = new (allocator.Allocate()) Uint64LinkNode(kTestValue);
        ASSERT_EQ(pointer->GetValue(), kTestValue);
    }
}

// Ensure blocks are reused after being deallocated.
TEST(ContiguousLinkNodeAllocatorTests, DeallocateAndReuseMemory) {
    // Test with a uint64_t
    for (size_t objectsPerBlock : kObjectsPerBlock) {
        ContiguousLinkNodeAllocator<uint64_t> allocator(objectsPerBlock);
        std::vector<uint64_t*> pointers;

        uint64_t kNumAllocations = objectsPerBlock * 2;

        for (uint64_t i = 0; i < kNumAllocations; i++) {
            pointers.push_back(new (allocator.Allocate()) uint64_t(i));
        }

        std::vector<uint64_t*> freeAllocations;
        // Choose three random locations to deallocate
        for (int i = 0; i < 3; i++) {
            freeAllocations.push_back(pointers[rand() % (kNumAllocations)]);
            allocator.Deallocate(freeAllocations[i]);
        }

        // Allocate three times with the test value. These should be inserted into the freed
        // locations in the reverse of how the locations were deallocated.
        for (int i = 2; i >= 0; i--) {
            new (allocator.Allocate()) uint64_t(kTestValue);
            ASSERT_EQ(*freeAllocations[i], kTestValue);
        }
    }

    // Test with a LinkNode
    for (size_t objectsPerBlock : kObjectsPerBlock) {
        ContiguousLinkNodeAllocator<Uint64LinkNode> allocator(objectsPerBlock);
        std::vector<Uint64LinkNode*> pointers;

        uint64_t kNumAllocations = objectsPerBlock * 2;

        for (uint64_t i = 0; i < kNumAllocations; i++) {
            pointers.push_back(new (allocator.Allocate()) Uint64LinkNode(i));
        }

        std::vector<Uint64LinkNode*> freeAllocations;
        // Choose three random locations to deallocate
        for (int i = 0; i < 3; i++) {
            freeAllocations.push_back(pointers[rand() % (kNumAllocations)]);
            allocator.Deallocate(freeAllocations[i]);
        }

        // Allocate three times with the test value. These should be inserted into the freed
        // locations in the reverse of how the locations were deallocated.
        for (int i = 2; i >= 0; i--) {
            new (allocator.Allocate()) Uint64LinkNode(kTestValue);
            ASSERT_EQ(freeAllocations[i]->GetValue(), kTestValue);
        }
    }
}

// Ensure that the allocator's underlying vectors are never re-allocated by ensuring a pointer stays
// stable after allocating enough to create another block.
TEST(ContiguousLinkNodeAllocatorTests, EnsurePointerStability) {
    // Test with a uint64_t
    for (size_t objectsPerBlock : kObjectsPerBlock) {
        ContiguousLinkNodeAllocator<uint64_t> allocator(objectsPerBlock);
        uint64_t* pointer = new (allocator.Allocate()) uint64_t(kTestValue);
        for (uint64_t i = 1; i < objectsPerBlock + 1; i++) {
            allocator.Allocate();
        }

        ASSERT_EQ(*pointer, kTestValue);
    }

    // Test with a LinkNode
    for (size_t objectsPerBlock : kObjectsPerBlock) {
        ContiguousLinkNodeAllocator<Uint64LinkNode> allocator(objectsPerBlock);
        Uint64LinkNode* pointer = new (allocator.Allocate()) Uint64LinkNode(kTestValue);
        for (uint64_t i = 1; i < objectsPerBlock + 1; i++) {
            allocator.Allocate();
        }

        ASSERT_EQ(pointer->GetValue(), kTestValue);
    }
}
