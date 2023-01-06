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

#include "gpgmm/common/ThreadPool.h"

#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/PlatformUtils.h"
#include "gpgmm/utils/Utils.h"

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

namespace gpgmm {

    static constexpr const char* kBackgroundThreadName = "GPGMM Background Thread";

    // Limit minimum running threads: one for allocation and another for budgeting.
    static constexpr uint32_t kMinThreadCount = 2u;

    using AsyncTask = std::pair<std::shared_ptr<VoidCallback>, std::shared_ptr<Event>>;

    class AsyncEventImpl final : public Event {
      public:
        AsyncEventImpl() = default;

        void Wait() override {
            TRACE_EVENT0(TraceEventCategory::kDefault, "Event.Wait");

            std::unique_lock<std::mutex> lock(mMutex);
            mCondition.wait(lock, [this] { return mIsSignaled; });
        }

        bool IsSignaled() override {
            std::unique_lock<std::mutex> lock(mMutex);
            return mIsSignaled;
        }

        void Signal() override {
            {
                std::unique_lock<std::mutex> lock(mMutex);
                mIsSignaled = true;
            }
            mCondition.notify_all();
        }

      private:
        std::mutex mMutex;
        std::condition_variable mCondition;
        bool mIsSignaled = false;
    };

    class AsyncTaskThreadPoolImpl final : public ThreadPool {
      public:
        AsyncTaskThreadPoolImpl(uint32_t minThreadCount, uint32_t maxThreadCount) {
            ASSERT(minThreadCount <= maxThreadCount);

            // Create the storage upfront so Resize can't modify the storage in-use by an existing
            // std::thread.
            mThreads.reserve(maxThreadCount);

            Resize(minThreadCount);
        }

        ~AsyncTaskThreadPoolImpl() override {
            Shutdown();
        }

        uint32_t GetCurrentThreadCount() const override {
            return mThreads.size();
        }

        uint32_t GetMaxThreadCount() const override {
            return mThreads.capacity();
        }

        void Resize(uint32_t threadCount) override {
            const uint32_t numThreadsToCreate = (GetCurrentThreadCount() < threadCount)
                                                    ? threadCount - GetCurrentThreadCount()
                                                    : 0u;

            if (numThreadsToCreate + GetCurrentThreadCount() > GetMaxThreadCount()) {
                return;
            }

            for (uint32_t threadIndex = 0; threadIndex < numThreadsToCreate; ++threadIndex) {
                // Concat the assigned thread index to the name for debugging.
                std::string threadNameWithIndex(kBackgroundThreadName);
                threadNameWithIndex += " ";
                threadNameWithIndex += std::to_string(mThreadIndex++);

                mThreads.push_back(std::thread([this, threadNameWithIndex]() {
                    SetThreadName(threadNameWithIndex.c_str());
                    TRACE_EVENT_METADATA1(TraceEventCategory::kMetadata, "thread_name", "name",
                                          threadNameWithIndex.c_str());
                    RunExecutionLoop();
                }));
            }
        }

        bool HasTasksToExecute() override {
            bool hasTasksToExecute;
            {
                std::unique_lock<std::mutex> lock(mQueueMutex);
                hasTasksToExecute = !mTaskQueue.empty();
            }
            return hasTasksToExecute;
        }

        void Shutdown() override {
            if (mThreads.size() == 0) {
                return;
            }

            // Inform thread to terminate after it finishes the current job, if any in progress.
            {
                std::unique_lock<std::mutex> lock(mQueueMutex);
                mStopQueueProcessingTasks = true;
            }

            // Wait for the threads to terminate.
            mQueueCondition.notify_all();
            for (std::thread& thread : mThreads) {
                thread.join();
            }

            mThreads.clear();
        }

      private:
        std::shared_ptr<Event> postTaskImpl(std::shared_ptr<VoidCallback> callback) override {
            std::shared_ptr<Event> event = std::make_shared<AsyncEventImpl>();
            {
                std::unique_lock<std::mutex> lock(mQueueMutex);
                mTaskQueue.push(std::make_pair(callback, event));
            }
            mQueueCondition.notify_one();
            return event;
        }

        void RunExecutionLoop() {
            for (;;) {
                AsyncTask task;
                {
                    std::unique_lock<std::mutex> lock(mQueueMutex);
                    mQueueCondition.wait(
                        lock, [this] { return !mTaskQueue.empty() || mStopQueueProcessingTasks; });
                    if (mStopQueueProcessingTasks) {
                        return;
                    }
                    task = mTaskQueue.front();
                    mTaskQueue.pop();
                }
                (*task.first)();  // Execute
                task.second->Signal();
            }
        }

        uint32_t mThreadIndex = 0;
        std::vector<std::thread> mThreads;

        std::mutex mQueueMutex;                   // Protects access for below members.
        std::condition_variable mQueueCondition;  // Allow threads to wait on new tasks.
        std::queue<AsyncTask> mTaskQueue;
        bool mStopQueueProcessingTasks = false;
    };

    // Event

    void Event::SetThreadPool(std::shared_ptr<ThreadPool> pool) {
        mPool = pool;
    }

    // ThreadPool

    // static
    std::shared_ptr<ThreadPool> ThreadPool::Create(uint32_t minThreadCount,
                                                   uint32_t maxThreadCount) {
        return std::shared_ptr<ThreadPool>(
            new AsyncTaskThreadPoolImpl(minThreadCount, maxThreadCount));
    }

    // static
    std::shared_ptr<Event> ThreadPool::PostTask(std::shared_ptr<ThreadPool> pool,
                                                std::shared_ptr<VoidCallback> task) {
        // Grow the pool only when tasks need processing and the thread limit hasn't been reached.
        const uint32_t currentThreadCount = pool->GetCurrentThreadCount();
        if (currentThreadCount == 0 ||
            (pool->HasTasksToExecute() && currentThreadCount < pool->GetMaxThreadCount())) {
            pool->Resize(currentThreadCount + 1);
        }

        // Ensure the pool is able to process the returned event by ensuring the event cannot
        // outlive it.
        std::shared_ptr<Event> event = pool->postTaskImpl(task);
        if (event != nullptr) {
            event->SetThreadPool(pool);
        }

        return event;
    }

    // TaskScheduler

    static TaskScheduler* sTaskScheduler = nullptr;
    static std::mutex sTaskSchedulerAccessMutex;

    TaskScheduler::TaskScheduler()
        : mThreadPool(new AsyncTaskThreadPoolImpl(
              kMinThreadCount,
              std::max(kMinThreadCount, std::thread::hardware_concurrency()))) {
    }

    // static
    TaskScheduler* TaskScheduler::GetOrCreateInstance() {
        std::lock_guard<std::mutex> lock(sTaskSchedulerAccessMutex);
        if (!sTaskScheduler) {
            sTaskScheduler = new TaskScheduler();
        }
        return sTaskScheduler;
    }

    // static
    void TaskScheduler::ReleaseInstanceForTesting() {
        std::lock_guard<std::mutex> lock(sTaskSchedulerAccessMutex);
        if (sTaskScheduler) {
            SafeDelete(sTaskScheduler);
        }
    }

    std::shared_ptr<Event> TaskScheduler::PostTask(std::shared_ptr<VoidCallback> task) {
        ASSERT(mThreadPool);
        return mThreadPool->PostTask(mThreadPool, task);
    }

}  // namespace gpgmm
