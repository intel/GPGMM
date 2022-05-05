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

namespace gpgmm {

    class AllocateMemoryTask : public VoidCallback {
      public:
        AllocateMemoryTask(MemoryAllocator* allocator, uint64_t requestSize, uint64_t alignment)
            : mAllocator(allocator), mRequestSize(requestSize), mAlignment(alignment) {
        }

        void operator()() override {
            mAllocation = mAllocator->TryAllocateMemory(mRequestSize, mAlignment, /*neverAllocate*/
                                                        false, true, false);
        }

        std::unique_ptr<MemoryAllocation> AcquireAllocation() {
            return std::move(mAllocation);
        }

      private:
        MemoryAllocator* const mAllocator;
        const uint64_t mRequestSize;
        const uint64_t mAlignment;

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

    std::unique_ptr<MemoryAllocation> MemoryAllocator::TryAllocateMemory(uint64_t requestSize,
                                                                         uint64_t alignment,
                                                                         bool neverAllocate,
                                                                         bool cacheSize,
                                                                         bool prefetchMemory) {
        ASSERT(false);
        return {};
    }

    std::shared_ptr<MemoryAllocationEvent> MemoryAllocator::TryAllocateMemoryAsync(
        uint64_t size,
        uint64_t alignment) {
        std::shared_ptr<AllocateMemoryTask> task =
            std::make_shared<AllocateMemoryTask>(this, size, alignment);
        return std::make_shared<MemoryAllocationEvent>(ThreadPool::PostTask(mThreadPool, task),
                                                       task);
    }

    void MemoryAllocator::ReleaseMemory() {
        std::lock_guard<std::mutex> lock(mMutex);
        if (GetNextInChain() != nullptr) {
            GetNextInChain()->ReleaseMemory();
        }
    }

    uint64_t MemoryAllocator::GetMemorySize() const {
        return kInvalidSize;
    }

    uint64_t MemoryAllocator::GetMemoryAlignment() const {
        return kInvalidOffset;
    }

    MEMORY_ALLOCATOR_INFO MemoryAllocator::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return mInfo;
    }

    const char* MemoryAllocator::GetTypename() const {
        return "MemoryAllocator";
    }

}  // namespace gpgmm
