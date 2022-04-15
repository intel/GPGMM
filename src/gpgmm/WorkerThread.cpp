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

#include "gpgmm/WorkerThread.h"

#include "gpgmm/TraceEvent.h"

#include <condition_variable>
#include <functional>
#include <thread>

namespace gpgmm {

    class AsyncEventImpl final : public Event {
      public:
        AsyncEventImpl() = default;

        void Wait() override {
            TRACE_EVENT0(TraceEventCategory::Default, "AsyncEventImpl.Wait");

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
        ~AsyncThreadPoolImpl() override = default;

        std::shared_ptr<Event> postTaskImpl(std::shared_ptr<VoidCallback> callback) override {
            std::shared_ptr<Event> event = std::make_shared<AsyncEventImpl>();
            std::thread thread([callback, event]() {
                TRACE_EVENT_METADATA1(TraceEventCategory::Metadata, "thread_name", "name",
                                      "GPGMM_ThreadPoolBackgroundWorker");
                (*callback)();
                event->Signal();
            });
            thread.detach();
            return event;
        }
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
        if (event != nullptr) {
            event->SetThreadPool(pool);
        }
        return event;
    }

}  // namespace gpgmm
