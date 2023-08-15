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

#ifndef SRC_GPGMM_COMMON_THREADPOOL_H_
#define SRC_GPGMM_COMMON_THREADPOOL_H_

#include "gpgmm/common/Error.h"
#include "gpgmm/utils/NonCopyable.h"

#include <memory>

namespace gpgmm {

    class VoidCallback : public NonCopyable {
      public:
        virtual ~VoidCallback() = default;

        // Define operator () that accepts no parameters ().
        virtual MaybeError operator()() = 0;
    };

    class ThreadPool;

    // An event that we can wait on.
    // Used for waiting for results or joining worker threads.
    class Event : public NonCopyable {
      public:
        Event() = default;
        virtual ~Event() = default;

        // Wait for the event to complete.
        // Blocks the calling thread indefinitely until the event gets signaled.
        virtual void Wait() = 0;

        // Check if event was signaled.
        // Event will be in signaled state once the event is completed.
        virtual bool IsSignaled() = 0;

        // Signals the event is ready.
        // If ready, wait() will not block.
        virtual void Signal() = 0;

        // Associates a thread pool with this event.
        void SetThreadPool(std::shared_ptr<ThreadPool> pool);

      private:
        std::shared_ptr<ThreadPool> mPool;
    };

    // Collection of threads that can process tasks as function call-backs.
    class ThreadPool : public NonCopyable {
      public:
        ThreadPool() = default;
        virtual ~ThreadPool() = default;

        // Creates a pool with up to |maxThreadCount| threads.
        static std::shared_ptr<ThreadPool> Create(uint32_t minThreadCount, uint32_t maxThreadCount);

        static std::shared_ptr<Event> PostTask(std::shared_ptr<ThreadPool> pool,
                                               std::shared_ptr<VoidCallback> task);

        // Returns True if threads in the pool have tasks to execute.
        virtual bool HasTasksToExecute() = 0;

        // Tells the pool to stop processing more tasks and to exit threads.
        virtual void Shutdown() = 0;

        // Returns the number of running threads in the pool.
        virtual uint32_t GetCurrentThreadCount() const = 0;

        // Returns the maximum number of running threads allowed in the pool.
        virtual uint32_t GetMaxThreadCount() const = 0;

        // Expands the size of the pool, to the specified number of threads.
        virtual void Resize(uint32_t threadCount) = 0;

      private:
        // Return event to wait on until the callback runs.
        virtual std::shared_ptr<Event> postTaskImpl(std::shared_ptr<VoidCallback> task) = 0;
    };

    // Singleton class to process tasks using a single thread pool.
    class TaskScheduler : public NonCopyable {
      public:
        static TaskScheduler* GetOrCreateInstance();
        std::shared_ptr<Event> PostTask(std::shared_ptr<VoidCallback> task);

        static void ReleaseInstanceForTesting();

      private:
        TaskScheduler();

        std::shared_ptr<ThreadPool> mThreadPool;
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_THREADPOOL_H_
