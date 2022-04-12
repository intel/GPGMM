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

#include "gpgmm/SegmentedMemoryAllocator.h"

#include "gpgmm/Debug.h"
#include "gpgmm/common/Assert.h"
#include "gpgmm/common/Utils.h"

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
            if (middle->value()->GetMemorySize() == size) {
                return middle;

            } else if (middle->value()->GetMemorySize() > size) {
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

    MemorySegment::MemorySegment(uint64_t memorySize) : LIFOMemoryPool(memorySize) {
    }

    MemorySegment::~MemorySegment() {
        if (IsInList()) {
            RemoveFromList();
        }
        ReleasePool();
    }

    // SegmentedMemoryAllocator

    SegmentedMemoryAllocator::SegmentedMemoryAllocator(
        std::unique_ptr<MemoryAllocator> memoryAllocator,
        uint64_t memoryAlignment)
        : MemoryAllocator(std::move(memoryAllocator)), mMemoryAlignment(memoryAlignment) {
    }

    SegmentedMemoryAllocator::~SegmentedMemoryAllocator() {
        auto curr = mFreeSegments.head();
        while (curr != mFreeSegments.end()) {
            auto next = curr->next();
            ASSERT(curr != nullptr);
            SafeDelete(curr->value());
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
            MemorySegment* newFreeSegment = new MemorySegment{memorySize};
            mFreeSegments.Append(newFreeSegment);
            return newFreeSegment;
        }

        ASSERT(existingFreeSegment->value() != nullptr);

        // Segment already exists, reuse it.
        if (existingFreeSegment->value()->GetMemorySize() == memorySize) {
            return existingFreeSegment->value();
        }

        MemorySegment* newFreeSegment = new MemorySegment{memorySize};

        // Or insert a new segment in sorted order.
        if (memorySize > existingFreeSegment->value()->GetMemorySize()) {
            newFreeSegment->InsertAfter(existingFreeSegment);
        } else {
            newFreeSegment->InsertBefore(existingFreeSegment);
        }

        return newFreeSegment;
    }

    std::unique_ptr<MemoryAllocation> SegmentedMemoryAllocator::TryAllocateMemory(
        uint64_t size,
        uint64_t alignment,
        bool neverAllocate,
        bool cacheSize,
        bool prefetchMemory) {
        TRACE_EVENT0(TraceEventCategory::Default, "SegmentedMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_CHECK_NONZERO(size);

        if (alignment != mMemoryAlignment) {
            DebugEvent("SegmentedMemoryAllocator.TryAllocateMemory",
                       ALLOCATOR_MESSAGE_ID_ALIGNMENT_MISMATCH)
                << "Allocation alignment does not match memory alignment.";
            return {};
        }

        MemorySegment* segment = GetOrCreateFreeSegment(size);
        ASSERT(segment != nullptr);

        std::unique_ptr<MemoryAllocation> allocation = segment->AcquireFromPool();
        if (allocation == nullptr) {
            GPGMM_TRY_ASSIGN(GetFirstChild()->TryAllocateMemory(
                                 size, mMemoryAlignment, neverAllocate, cacheSize, prefetchMemory),
                             allocation);
        } else {
            mInfo.FreeMemoryUsage -= allocation->GetSize();
        }

        mInfo.UsedMemoryCount++;
        mInfo.UsedMemoryUsage += allocation->GetSize();

        MemoryBase* memory = allocation->GetMemory();
        ASSERT(memory != nullptr);

        memory->SetPool(segment);

        return std::make_unique<MemoryAllocation>(this, memory);
    }

    void SegmentedMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "SegmentedMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        ASSERT(allocation != nullptr);

        mInfo.FreeMemoryUsage += allocation->GetSize();
        mInfo.UsedMemoryCount--;
        mInfo.UsedMemoryUsage -= allocation->GetSize();

        MemoryBase* memory = allocation->GetMemory();
        ASSERT(memory != nullptr);

        MemoryPool* pool = memory->GetPool();
        ASSERT(pool != nullptr);

        pool->ReturnToPool(std::make_unique<MemoryAllocation>(GetFirstChild(), memory));
    }

    void SegmentedMemoryAllocator::ReleaseMemory() {
        std::lock_guard<std::mutex> lock(mMutex);

        for (auto node = mFreeSegments.head(); node != mFreeSegments.end(); node = node->next()) {
            MemorySegment* segment = node->value();
            ASSERT(segment != nullptr);
            segment->ReleasePool();
        }
    }

    uint64_t SegmentedMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAlignment;
    }

    uint64_t SegmentedMemoryAllocator::GetSegmentSizeForTesting() const {
        std::lock_guard<std::mutex> lock(mMutex);

        uint64_t count = 0;
        for (auto node = mFreeSegments.head(); node != mFreeSegments.end(); node = node->next()) {
            count += 1;
        }
        return count;
    }

}  // namespace gpgmm
