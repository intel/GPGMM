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

#include "src/SegmentedMemoryAllocator.h"

#include "common/Assert.h"
#include "src/LIFOMemoryPool.h"

namespace gpgmm {

    // Helper for FindSegment to find the middle of a linked-list.
    LinkNode<MemorySegment>* GetMiddleSegment(LinkNode<MemorySegment>* start,
                                              LinkNode<MemorySegment>* end) {
        LinkNode<MemorySegment>* slow = start;
        LinkNode<MemorySegment>* fast = start->next();
        while (fast != end) {
            fast = fast->next();
            if (fast != end) {
                slow = slow->next();
                fast = fast->next();
            }
        }

        return slow;
    }

    // Perform a slower, O(n) binary search, over a non-contigious array (linked-list).
    LinkNode<MemorySegment>* FindSegment(LinkNode<MemorySegment>* start,
                                         LinkNode<MemorySegment>* end,
                                         uint64_t size) {
        LinkNode<MemorySegment>* left = start;
        LinkNode<MemorySegment>* right = end;

        while (left != right) {
            LinkNode<MemorySegment>* middle = GetMiddleSegment(left, right);
            if (middle == nullptr) {
                return nullptr;
            }
            if (middle->value()->GetSize() == size) {
                return middle;

            } else if (middle->value()->GetSize() > size) {
                // Smaller then middle, go left.
                right = middle;

            } else {
                // Larger then middle, go right.
                left = middle->next();
            }
        }
        return left;
    }

    // MemorySegment

    MemorySegment::MemorySegment(uint64_t memorySize, std::unique_ptr<MemoryPool> pool)
        : mMemorySize(memorySize), mPool(std::move(pool)) {
    }

    MemorySegment::~MemorySegment() {
        if (IsInList()) {
            RemoveFromList();
        }

        mPool->ReleasePool();
    }

    uint64_t MemorySegment::GetSize() const {
        return mMemorySize;
    }

    MemoryPool* MemorySegment::GetPool() const {
        return mPool.get();
    }

    // SegmentedMemoryAllocator

    SegmentedMemoryAllocator::SegmentedMemoryAllocator(MemoryAllocator* memoryAllocator,
                                                       uint64_t memoryAlignment)
        : mMemoryAllocator(memoryAllocator), mMemoryAlignment(memoryAlignment) {
    }

    SegmentedMemoryAllocator::~SegmentedMemoryAllocator() {
        auto curr = mFreeSegments.head();
        while (curr != mFreeSegments.end()) {
            auto next = curr->next();
            ASSERT(curr != nullptr);
            delete curr->value();
            curr = next;
        }

        ASSERT(mFreeSegments.empty());
    }

    MemorySegment* SegmentedMemoryAllocator::GetOrCreateFreeSegment(uint64_t memorySize) {
        LinkNode<MemorySegment>* existingFreeSegment =
            FindSegment(mFreeSegments.head(), mFreeSegments.tail(), memorySize);

        // List is empty, append it at end.
        if (existingFreeSegment == mFreeSegments.end()) {
            ASSERT(mFreeSegments.empty());
            MemorySegment* newFreeSegment =
                new MemorySegment{memorySize, std::make_unique<LIFOMemoryPool>()};
            mFreeSegments.Append(newFreeSegment);
            return newFreeSegment;
        }

        ASSERT(existingFreeSegment->value() != nullptr);

        // Segment already exists, reuse it.
        if (existingFreeSegment->value()->GetSize() == memorySize) {
            return existingFreeSegment->value();
        }

        MemorySegment* newFreeSegment =
            new MemorySegment{memorySize, std::make_unique<LIFOMemoryPool>()};

        // Or insert a new segment in sorted order.
        if (memorySize > existingFreeSegment->value()->GetSize()) {
            newFreeSegment->InsertAfter(existingFreeSegment);
        } else {
            newFreeSegment->InsertBefore(existingFreeSegment);
        }

        return newFreeSegment;
    }

    std::unique_ptr<MemoryAllocation> SegmentedMemoryAllocator::AllocateMemory(uint64_t size,
                                                                               uint64_t alignment,
                                                                               bool neverAllocate) {
        if (size == 0 || alignment != mMemoryAlignment) {
            return {};
        }

        MemorySegment* segment = GetOrCreateFreeSegment(size);
        ASSERT(segment != nullptr);

        std::unique_ptr<MemoryAllocation> allocation = segment->GetPool()->AcquireFromPool();
        if (allocation == nullptr) {
            allocation = mMemoryAllocator->AllocateMemory(size, mMemoryAlignment, neverAllocate);
            if (allocation == nullptr) {
                return nullptr;
            }
        }

        allocation->GetMemory()->SetPool(segment->GetPool());

        return std::make_unique<MemoryAllocation>(this, allocation->GetMemory());
    }

    void SegmentedMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        ASSERT(allocation != nullptr);

        MemoryBase* memory = allocation->GetMemory();
        ASSERT(memory != nullptr);

        MemoryPool* pool = memory->GetPool();
        ASSERT(pool != nullptr);

        pool->ReturnToPool(
            std::make_unique<MemoryAllocation>(mMemoryAllocator, allocation->GetMemory()));
    }

    void SegmentedMemoryAllocator::ReleaseMemory() {
        for (auto node = mFreeSegments.head(); node != mFreeSegments.end(); node = node->next()) {
            MemorySegment* segment = node->value();
            ASSERT(segment != nullptr);

            MemoryPool* pool = segment->GetPool();
            ASSERT(pool != nullptr);

            pool->ReleasePool();
        }
    }

    uint64_t SegmentedMemoryAllocator::GetPoolSizeForTesting() const {
        uint64_t count = 0;
        for (auto node = mFreeSegments.head(); node != mFreeSegments.end(); node = node->next()) {
            MemorySegment* segment = node->value();
            ASSERT(segment != nullptr);

            MemoryPool* pool = segment->GetPool();
            ASSERT(pool != nullptr);

            count += pool->GetPoolSize();
        }
        return count;
    }

}  // namespace gpgmm
