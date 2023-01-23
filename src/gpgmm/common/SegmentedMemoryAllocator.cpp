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

#include "gpgmm/common/SegmentedMemoryAllocator.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Math.h"
#include "gpgmm/utils/Utils.h"

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
        mFreeSegments.clear();
    }

    MemorySegment* SegmentedMemoryAllocator::GetOrCreateFreeSegment(uint64_t memorySize) {
        LinkNode<MemorySegment>* existingFreeSegment =
            FindSegment(mFreeSegments.head(), mFreeSegments.tail(), memorySize);

        // List is empty, append it at end.
        if (existingFreeSegment == mFreeSegments.end()) {
            ASSERT(mFreeSegments.empty());
            MemorySegment* newFreeSegment = new MemorySegment{memorySize};
            newFreeSegment->InsertAfter(mFreeSegments.tail());
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

    ResultOrError<std::unique_ptr<MemoryAllocation>> SegmentedMemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "SegmentedMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_INVALID_IF(!ValidateRequest(request));

        const uint64_t memorySize = AlignTo(request.SizeInBytes, mMemoryAlignment);
        MemorySegment* segment = GetOrCreateFreeSegment(memorySize);
        ASSERT(segment != nullptr);

        MemoryAllocation allocation = segment->AcquireFromPool();
        if (allocation == GPGMM_INVALID_ALLOCATION) {
            std::unique_ptr<MemoryAllocation> allocationPtr;
            GPGMM_TRY_ASSIGN(GetNextInChain()->TryAllocateMemory(request), allocationPtr);
            allocation = *allocationPtr;
        } else {
            mStats.FreeMemoryUsage -= allocation.GetSize();
        }

        mStats.UsedMemoryCount++;
        mStats.UsedMemoryUsage += allocation.GetSize();

        MemoryBase* memory = allocation.GetMemory();
        ASSERT(memory != nullptr);
        memory->SetPool(segment);

        return std::make_unique<MemoryAllocation>(this, memory, request.SizeInBytes);
    }

    void SegmentedMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "SegmentedMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        ASSERT(allocation != nullptr);

        const uint64_t& allocationSize = allocation->GetSize();
        mStats.FreeMemoryUsage += allocationSize;
        mStats.UsedMemoryCount--;
        mStats.UsedMemoryUsage -= allocationSize;

        MemoryBase* memory = allocation->GetMemory();
        ASSERT(memory != nullptr);

        MemoryPoolBase* pool = memory->GetPool();
        ASSERT(pool != nullptr);

        static_cast<MemorySegment*>(pool)->ReturnToPool(
            MemoryAllocation(GetNextInChain(), memory, allocation->GetRequestSize()));
    }

    uint64_t SegmentedMemoryAllocator::ReleaseMemory(uint64_t bytesToRelease) {
        std::lock_guard<std::mutex> lock(mMutex);

        uint64_t totalBytesReleased = 0;
        for (auto& node : mFreeSegments) {
            MemorySegment* segment = node.value();
            ASSERT(segment != nullptr);
            const uint64_t bytesReleasedPerSegment = segment->ReleasePool(bytesToRelease);
            bytesToRelease -= bytesReleasedPerSegment;
            mStats.FreeMemoryUsage -= bytesReleasedPerSegment;
            totalBytesReleased += bytesReleasedPerSegment;

            if (totalBytesReleased >= bytesToRelease) {
                break;
            }
        }

        return totalBytesReleased;
    }

    uint64_t SegmentedMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAlignment;
    }

    uint64_t SegmentedMemoryAllocator::GetSegmentSizeForTesting() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return std::distance(mFreeSegments.begin(), mFreeSegments.end());
    }

    const char* SegmentedMemoryAllocator::GetTypename() const {
        return "SegmentedMemoryAllocator";
    }

}  // namespace gpgmm
