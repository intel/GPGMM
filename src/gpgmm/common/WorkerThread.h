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

#ifndef GPGMM_COMMON_WORKERTHREAD_H_
#define GPGMM_COMMON_WORKERTHREAD_H_

#include "gpgmm/utils/NonCopyable.h"

#include <memory>

namespace gpgmm {

    class VoidCallback : public NonCopyable {
      public:
        virtual ~VoidCallback() = default;

        // Define operator () that accepts no parameters ().
        virtual void operator()() = 0;
    };

    class ThreadPool;

    // An event that we can wait on, useful for joining worker threads.
    class Event : public NonCopyable {
      public:
        Event() = default;
        virtual ~Event() = default;

        // Blocks calling thread indefinitely until |this| event is signaled.
        virtual void Wait() = 0;

        // Checks if |this| event was signaled.
        virtual bool IsSignaled() = 0;

        // Signals the event is ready. If ready, wait() will not block.
        virtual void Signal() = 0;

        void SetThreadPool(std::shared_ptr<ThreadPool> pool);

      private:
        std::shared_ptr<ThreadPool> mPool;
    };

    class ThreadPool : public NonCopyable {
      public:
        ThreadPool() = default;
        virtual ~ThreadPool() = default;

        static std::shared_ptr<ThreadPool> Create();

        static std::shared_ptr<Event> PostTask(std::shared_ptr<ThreadPool> pool,
                                               std::shared_ptr<VoidCallback> callback);

      private:
        // Return event to wait on until the callback runs.
        virtual std::shared_ptr<Event> postTaskImpl(std::shared_ptr<VoidCallback> callback) = 0;

        // Check if the thread pool needs to start running a worker thread.
        virtual void checkAndRunPendingTasks() = 0;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_WORKERTHREAD_H_
