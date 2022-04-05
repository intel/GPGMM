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

#include "gpgmm/MemoryAllocator.h"

namespace gpgmm {

    class AllocateMemoryTask : public VoidCallback {
      public:
        AllocateMemoryTask(MemoryAllocator* allocator, uint64_t size, uint64_t alignment)
            : mAllocator(allocator), mSize(size), mAlignment(alignment) {
        }

        void operator()() override {
            mAllocation = mAllocator->TryAllocateMemory(mSize, mAlignment, /*neverAllocate*/
                                                        false, true, false);
        }

        std::unique_ptr<MemoryAllocation> AcquireAllocation() {
            return std::move(mAllocation);
        }

      private:
        MemoryAllocator* const mAllocator;
        const uint64_t mSize;
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

    MemoryAllocator::MemoryAllocator(std::unique_ptr<MemoryAllocator> child)
        : mThreadPool(ThreadPool::Create()) {
        AppendChild(std::move(child));
    }

    std::unique_ptr<MemoryAllocation> MemoryAllocator::TryAllocateMemory(uint64_t size,
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
        for (auto alloc = mChildren.head(); alloc != mChildren.end(); alloc = alloc->next()) {
            alloc->value()->ReleaseMemory();
        }
    }

    uint64_t MemoryAllocator::GetMemorySize() const {
        return kInvalidSize;
    }

    uint64_t MemoryAllocator::GetMemoryAlignment() const {
        return kInvalidOffset;
    }

    MEMORY_ALLOCATOR_INFO MemoryAllocator::QueryInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return mInfo;
    }

}  // namespace gpgmm
