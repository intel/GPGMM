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

#include "gpgmm/common/MemoryAllocator.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/JSONSerializer.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm {

    class AllocateMemoryTask : public VoidCallback {
      public:
        AllocateMemoryTask(MemoryAllocator* allocator, const MemoryAllocationRequest& request)
            : mAllocator(allocator), mRequest(request) {
        }

        void operator()() override {
            std::lock_guard<std::mutex> lock(mAllocationMutex);
            mAllocation = mAllocator->TryAllocateMemory(mRequest);
        }

        ResultOrError<std::unique_ptr<MemoryAllocation>> AcquireAllocation() {
            std::lock_guard<std::mutex> lock(mAllocationMutex);
            return std::move(mAllocation);
        }

      private:
        MemoryAllocator* const mAllocator;
        const MemoryAllocationRequest mRequest;

        std::mutex mAllocationMutex;
        ResultOrError<std::unique_ptr<MemoryAllocation>> mAllocation;
    };

    // MemoryAllocatorStats

    MemoryAllocatorStats& MemoryAllocatorStats::operator+=(const MemoryAllocatorStats& rhs) {
        UsedBlockCount += rhs.UsedBlockCount;
        UsedBlockUsage += rhs.UsedBlockUsage;
        FreeMemoryUsage += rhs.FreeMemoryUsage;
        UsedMemoryUsage += rhs.UsedMemoryUsage;
        UsedMemoryCount += rhs.UsedMemoryCount;

        PrefetchedMemoryMisses += rhs.PrefetchedMemoryMisses;
        PrefetchedMemoryMissesEliminated += rhs.PrefetchedMemoryMissesEliminated;

        SizeCacheMisses += rhs.SizeCacheMisses;
        SizeCacheHits += rhs.SizeCacheHits;

        return *this;
    }

    // MemoryAllocationEvent

    MemoryAllocationEvent::MemoryAllocationEvent(std::shared_ptr<Event> event,
                                                 std::shared_ptr<AllocateMemoryTask> task)
        : mTask(task), mEvent(event) {
    }

    void MemoryAllocationEvent::Wait() {
        mEvent->Wait();
    }

    bool MemoryAllocationEvent::IsSignaled() {
        return mEvent->IsSignaled();
    }

    void MemoryAllocationEvent::Signal() {
        return mEvent->Signal();
    }

    ResultOrError<std::unique_ptr<MemoryAllocation>> MemoryAllocationEvent::AcquireAllocation()
        const {
        return mTask->AcquireAllocation();
    }

    // MemoryAllocator

    MemoryAllocator::MemoryAllocator() {
    }

    MemoryAllocator::MemoryAllocator(std::unique_ptr<MemoryAllocator> next) {
        InsertIntoChain(std::move(next));
    }

    MemoryAllocator::~MemoryAllocator() {
#if defined(GPGMM_ENABLE_ALLOCATOR_LEAK_CHECKS)
        // If memory cannot be reused by a (parent) allocator, ensure no used memory leaked.
        if (GetParent() == nullptr) {
            ASSERT(mStats.UsedBlockUsage == 0u);
            ASSERT(mStats.UsedBlockCount == 0u);
            ASSERT(mStats.UsedMemoryCount == 0u);
            ASSERT(mStats.UsedMemoryUsage == 0u);
        }
#endif

        // Deletes adjacent node recursively (post-order).
        if (mNext != nullptr) {
            SafeDelete(mNext);
        }

        if (IsInList()) {
            RemoveFromList();
        }
    }

    ResultOrError<std::unique_ptr<MemoryAllocation>> MemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        ASSERT(false);
        return {};
    }

    std::unique_ptr<MemoryAllocation> MemoryAllocator::TryAllocateMemoryForTesting(
        const MemoryAllocationRequest& request) {
        return TryAllocateMemory(request).AcquireResult();
    }

    std::shared_ptr<MemoryAllocationEvent> MemoryAllocator::TryAllocateMemoryAsync(
        const MemoryAllocationRequest& request) {
        std::shared_ptr<AllocateMemoryTask> task =
            std::make_shared<AllocateMemoryTask>(this, request);
        return std::make_shared<MemoryAllocationEvent>(
            TaskScheduler::GetOrCreateInstance()->PostTask(task), task);
    }

    uint64_t MemoryAllocator::ReleaseMemory(uint64_t bytesToRelease) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (GetNextInChain() != nullptr) {
            return GetNextInChain()->ReleaseMemory(bytesToRelease);
        }
        return 0;
    }

    uint64_t MemoryAllocator::GetMemorySize() const {
        return kInvalidSize;
    }

    uint64_t MemoryAllocator::GetMemoryAlignment() const {
        return kNoRequiredAlignment;
    }

    MemoryAllocatorStats MemoryAllocator::GetStats() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return mStats;
    }

    const char* MemoryAllocator::GetTypename() const {
        return "MemoryAllocator";
    }

    bool MemoryAllocator::ValidateRequest(const MemoryAllocationRequest& request) const {
        ASSERT(request.SizeInBytes > 0 && request.Alignment > 0);

        // Check request size cannot overflow.
        if (request.SizeInBytes > std::numeric_limits<uint64_t>::max() - (request.Alignment - 1)) {
            DebugLog(MessageId::kSizeExceeded, false, GetTypename(), this)
                << "Requested size rejected due to overflow: " + std::to_string(request.SizeInBytes)
                << " bytes.";
            return false;
        }

        // Check request size cannot overflow |this| memory allocator.
        const uint64_t alignedSize = AlignTo(request.SizeInBytes, request.Alignment);
        if (GetMemorySize() != kInvalidSize && alignedSize > GetMemorySize()) {
            DebugLog(MessageId::kSizeExceeded, false, GetTypename(), this)
                << "Requested size exceeds memory size (" + std::to_string(alignedSize) + " vs " +
                       std::to_string(GetMemorySize()) + " bytes).";
            return false;
        }

        // Check request size has compatible alignment with |this| memory allocator.
        // Alignment value of 1 means no alignment required.
        if (GetMemoryAlignment() == 0 ||
            (GetMemoryAlignment() > 1 && !IsAligned(GetMemoryAlignment(), request.Alignment))) {
            DebugLog(MessageId::kAlignmentMismatch, false, GetTypename(), this)
                << "Requested alignment exceeds memory alignment (" +
                       std::to_string(request.Alignment) + " vs " +
                       std::to_string(GetMemoryAlignment()) + " bytes).";
            return false;
        }

        return true;
    }

    MemoryAllocator* MemoryAllocator::GetNextInChain() const {
        return static_cast<MemoryAllocator*>(mNext);
    }

    MemoryAllocator* MemoryAllocator::GetParent() const {
        return mParent;
    }

    void MemoryAllocator::InsertIntoChain(std::unique_ptr<MemoryAllocator> next) {
        ASSERT(next != nullptr);
        next->mParent = this->value();
        mNext = next.release();
    }

    void MemoryAllocator::CheckAndReportAllocationMisalignment(const MemoryAllocation& allocation) {
        if (allocation.GetSize() > allocation.GetRequestSize()) {
            WarningLog(MessageId::kAlignmentMismatch)
                << "Allocation is larger then the requested size (" +
                       std::to_string(allocation.GetSize()) + " vs " +
                       std::to_string(allocation.GetRequestSize()) + " bytes).";
        }
    }

}  // namespace gpgmm
