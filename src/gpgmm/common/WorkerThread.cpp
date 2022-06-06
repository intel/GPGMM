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

#include "gpgmm/common/WorkerThread.h"

#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Assert.h"

#include <condition_variable>
#include <functional>
#include <queue>
#include <thread>

namespace gpgmm {

    class AsyncEventImpl final : public Event {
      public:
        AsyncEventImpl() = default;

        void Wait() override {
            TRACE_EVENT0(TraceEventCategory::Default, "AsyncEvent.Wait");

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

    class AsyncThreadPoolImpl final : public ThreadPool {
      public:
        AsyncThreadPoolImpl() = default;

        void checkAndRunPendingTasks() override {
            if (mIsRunning) {
                return;
            }
            mIsRunning = true;
            mWorkerThread = std::thread([this]() { ProcessTasksInWorkerThread(); });
        }

        ~AsyncThreadPoolImpl() override {
            if (!mIsRunning) {
                return;
            }

            {
                std::unique_lock<std::mutex> lock(mMutex);
                mShouldTerminate = true;
            }

            mCondition.notify_all();
            ASSERT(mWorkerThread.joinable());
            mWorkerThread.join();
        }

        std::shared_ptr<Event> postTaskImpl(std::shared_ptr<VoidCallback> callback) override {
            std::shared_ptr<Event> event = std::make_shared<AsyncEventImpl>();
            {
                std::unique_lock<std::mutex> lock(mMutex);
                mTaskQueue.push(std::make_pair(event, callback));
            }

            mCondition.notify_all();
            return event;
        }

        void ProcessTasksInWorkerThread() {
            TRACE_EVENT_METADATA1(TraceEventCategory::Metadata, "thread_name", "name",
                                  "GPGMM_ThreadPoolBackgroundWorker");
            while (true) {
                std::unique_lock<std::mutex> lock(mMutex);
                mCondition.wait(lock, [this] { return !mTaskQueue.empty() || mShouldTerminate; });
                if (mShouldTerminate) {
                    break;
                }

                auto task = mTaskQueue.front();
                mTaskQueue.pop();

                auto event = task.first;
                auto callback = task.second;

                (*callback)();
                event->Signal();

                lock.unlock();
                mCondition.notify_all();
            }
        }

        bool mIsRunning = false;

        // Protect access from the main and worker thread for shared class members.
        std::mutex mMutex;

        bool mShouldTerminate = false;
        std::condition_variable mCondition;
        std::thread mWorkerThread;
        std::queue<std::pair<std::shared_ptr<Event>, std::shared_ptr<VoidCallback>>> mTaskQueue;
    };

    // Event

    void Event::SetThreadPool(std::shared_ptr<ThreadPool> pool) {
        mPool = pool;
    }

    // ThreadPool

    // static
    std::shared_ptr<ThreadPool> ThreadPool::Create() {
        return std::shared_ptr<ThreadPool>(new AsyncThreadPoolImpl());
    }

    // static
    std::shared_ptr<Event> ThreadPool::PostTask(std::shared_ptr<ThreadPool> pool,
                                                std::shared_ptr<VoidCallback> callback) {
        std::shared_ptr<Event> event = pool->postTaskImpl(callback);
        pool->checkAndRunPendingTasks();
        if (event != nullptr) {
            event->SetThreadPool(pool);
        }
        return event;
    }

}  // namespace gpgmm
