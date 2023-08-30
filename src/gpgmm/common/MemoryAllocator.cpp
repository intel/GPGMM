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
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm {

    class AllocateMemoryTask : public VoidCallback {
      public:
        AllocateMemoryTask(MemoryAllocatorBase* allocator, const MemoryAllocationRequest& request)
            : mAllocator(allocator), mRequest(request) {
        }

        MaybeError operator()() override {
            std::lock_guard<std::mutex> lock(mAllocationMutex);
            mAllocation = mAllocator->TryAllocateMemory(mRequest);
            return mAllocation.GetErrorCode();
        }

        ResultOrError<std::unique_ptr<MemoryAllocationBase>> AcquireAllocation() {
            std::lock_guard<std::mutex> lock(mAllocationMutex);
            return std::move(mAllocation);
        }

      private:
        MemoryAllocatorBase* const mAllocator;
        const MemoryAllocationRequest mRequest;

        std::mutex mAllocationMutex;
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> mAllocation;
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

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> MemoryAllocationEvent::AcquireAllocation()
        const {
        return mTask->AcquireAllocation();
    }

    // MemoryAllocatorBase

    MemoryAllocatorBase::MemoryAllocatorBase() : RefCounted(0) {
    }

    MemoryAllocatorBase::MemoryAllocatorBase(ScopedRef<MemoryAllocatorBase> next) : RefCounted(0) {
        InsertIntoChain(next);
    }

    MemoryAllocatorBase::~MemoryAllocatorBase() {
#if defined(GPGMM_ENABLE_ALLOCATOR_LEAK_CHECKS)
        // If memory cannot be reused by a (parent) allocator, ensure no used memory leaked.
        if (GetParent() == nullptr) {
            ASSERT(mStats.UsedBlockUsage == 0u);
            ASSERT(mStats.UsedBlockCount == 0u);
            ASSERT(mStats.UsedMemoryCount == 0u);
            ASSERT(mStats.UsedMemoryUsage == 0u);
        }
#endif

        if (IsInList()) {
            RemoveFromList();
        }
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>> MemoryAllocatorBase::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        ASSERT(false);
        return {};
    }

    std::unique_ptr<MemoryAllocationBase> MemoryAllocatorBase::TryAllocateMemoryForTesting(
        const MemoryAllocationRequest& request) {
        return TryAllocateMemory(request).AcquireResult();
    }

    std::shared_ptr<MemoryAllocationEvent> MemoryAllocatorBase::TryAllocateMemoryAsync(
        const MemoryAllocationRequest& request) {
        std::shared_ptr<AllocateMemoryTask> task =
            std::make_shared<AllocateMemoryTask>(this, request);
        return std::make_shared<MemoryAllocationEvent>(
            TaskScheduler::GetOrCreateInstance()->PostTask(task), task);
    }

    uint64_t MemoryAllocatorBase::ReleaseMemory(uint64_t bytesToRelease) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (GetNextInChain() != nullptr) {
            return GetNextInChain()->ReleaseMemory(bytesToRelease);
        }
        return 0;
    }

    uint64_t MemoryAllocatorBase::GetMemorySize() const {
        return kInvalidSize;
    }

    uint64_t MemoryAllocatorBase::GetMemoryAlignment() const {
        return kNoRequiredAlignment;
    }

    MemoryAllocatorStats MemoryAllocatorBase::GetStats() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return mStats;
    }

    MaybeError MemoryAllocatorBase::ValidateRequest(const MemoryAllocationRequest& request) const {
        // Check for non-zero size and alignment.
        GPGMM_RETURN_ERROR_IF(this, request.SizeInBytes == 0, "Request cannot have zero size.",
                              ErrorCode::kInvalidArgument);
        GPGMM_RETURN_ERROR_IF(this, request.Alignment == 0, "Request cannot have zero alignment.",
                              ErrorCode::kInvalidArgument);

        // Check request size cannot overflow.
        GPGMM_RETURN_ERROR_IF(
            this,
            request.SizeInBytes > std::numeric_limits<uint64_t>::max() - (request.Alignment - 1),
            "Requested size invalid due to overflow: " +
                GetBytesToSizeInUnits(request.SizeInBytes) + ".",
            ErrorCode::kSizeExceeded);

        // Check request size cannot exceed the memory size of |this| memory allocator.
        const uint64_t requestedAlignedSize = AlignTo(request.SizeInBytes, request.Alignment);
        GPGMM_RETURN_ERROR_IF(
            this, GetMemorySize() != kInvalidSize && requestedAlignedSize > GetMemorySize(),
            "Requested size, after alignment, exceeds memory size: " +
                GetBytesToSizeInUnits(requestedAlignedSize) + " vs " +
                GetBytesToSizeInUnits(GetMemorySize()) + ".",
            ErrorCode::kSizeExceeded);

        // Check request size has compatible alignment with |this| memory allocator.
        GPGMM_RETURN_ERROR_IF(
            this,
            GetMemoryAlignment() != kNoRequiredAlignment &&
                !IsAligned(GetMemoryAlignment(), request.Alignment),
            "Requested alignment exceeds memory alignment: " + std::to_string(request.Alignment) +
                " vs " + std::to_string(GetMemoryAlignment()) + ".",
            ErrorCode::kSizeExceeded);

        return {};
    }

    MemoryAllocatorBase* MemoryAllocatorBase::GetNextInChain() const {
        return mNext.Get();
    }

    MemoryAllocatorBase* MemoryAllocatorBase::GetParent() const {
        return mParent;
    }

    void MemoryAllocatorBase::InsertIntoChain(ScopedRef<MemoryAllocatorBase> next) {
        std::lock_guard<std::mutex> lock(mMutex);
        ASSERT(next != nullptr);
        next->mParent = this->value();
        mNext = next;
    }

}  // namespace gpgmm
