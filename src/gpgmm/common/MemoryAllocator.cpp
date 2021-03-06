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
            mAllocation = mAllocator->TryAllocateMemory(mRequest);
        }

        std::unique_ptr<MemoryAllocation> AcquireAllocation() {
            return std::move(mAllocation);
        }

      private:
        MemoryAllocator* const mAllocator;
        const MemoryAllocationRequest mRequest;

        std::unique_ptr<MemoryAllocation> mAllocation;
    };

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

    std::unique_ptr<MemoryAllocation> MemoryAllocationEvent::AcquireAllocation() const {
        return mTask->AcquireAllocation();
    }

    // MemoryAllocator

    MemoryAllocator::MemoryAllocator() : mThreadPool(ThreadPool::Create()) {
    }

    MemoryAllocator::MemoryAllocator(std::unique_ptr<MemoryAllocator> next)
        : AllocatorNode(std::move(next)), mThreadPool(ThreadPool::Create()) {
    }

    MemoryAllocator::~MemoryAllocator() {
        // If memory cannot be reused by a (parent) allocator, ensure no used memory leaked.
        if (GetParent() == nullptr) {
            ASSERT(mInfo.UsedBlockUsage == 0u);
            ASSERT(mInfo.UsedBlockCount == 0u);
            ASSERT(mInfo.UsedMemoryCount == 0u);
            ASSERT(mInfo.UsedMemoryUsage == 0u);
        }
    }

    std::unique_ptr<MemoryAllocation> MemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        ASSERT(false);
        return {};
    }

    std::shared_ptr<MemoryAllocationEvent> MemoryAllocator::TryAllocateMemoryAsync(
        const MemoryAllocationRequest& request) {
        std::shared_ptr<AllocateMemoryTask> task =
            std::make_shared<AllocateMemoryTask>(this, request);
        return std::make_shared<MemoryAllocationEvent>(
            ThreadPool::PostTask(mThreadPool, task, "GPGMM_ThreadPrefetchWorker"), task);
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

    MemoryAllocatorInfo MemoryAllocator::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return mInfo;
    }

    const char* MemoryAllocator::GetTypename() const {
        return "MemoryAllocator";
    }

    bool MemoryAllocator::ValidateRequest(const MemoryAllocationRequest& request) const {
        ASSERT(request.SizeInBytes > 0 && request.Alignment > 0);

        // Check request size cannot overflow.
        if (request.SizeInBytes > std::numeric_limits<uint64_t>::max() - (request.Alignment - 1)) {
            DebugEvent(GetTypename(), EventMessageId::SizeExceeded)
                << "Requested size rejected due to overflow: " + std::to_string(request.SizeInBytes)
                << " bytes.";
            return false;
        }

        // Check request size cannot overflow |this| memory allocator.
        const uint64_t alignedSize = AlignTo(request.SizeInBytes, request.Alignment);
        if (GetMemorySize() != kInvalidSize && alignedSize > GetMemorySize()) {
            DebugEvent(GetTypename(), EventMessageId::SizeExceeded)
                << "Requested size exceeds memory size (" + std::to_string(alignedSize) + " vs " +
                       std::to_string(GetMemorySize()) + " bytes).";
            return false;
        }

        // Check request size has compatible alignment with |this| memory allocator.
        // Alignment value of 1 means no alignment required.
        if (GetMemoryAlignment() == 0 ||
            (GetMemoryAlignment() > 1 && !IsAligned(GetMemoryAlignment(), request.Alignment))) {
            DebugEvent(GetTypename(), EventMessageId::AlignmentMismatch)
                << "Requested alignment exceeds memory alignment (" +
                       std::to_string(request.Alignment) + " vs " +
                       std::to_string(GetMemoryAlignment()) + " bytes).";
            return false;
        }

        return true;
    }

}  // namespace gpgmm
