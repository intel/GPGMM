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

    /** \brief An event that we can wait on.

    Used for waiting for results or joining worker threads.
    */
    class Event : public NonCopyable {
      public:
        Event() = default;
        virtual ~Event() = default;

        /** \brief Wait for the event to complete.

        Wait blocks the calling thread indefinitely until the event gets signaled.
        */
        virtual void Wait() = 0;

        /** \brief Check if event was signaled.

        Event will be in signaled state once the event is completed.
        */
        virtual bool IsSignaled() = 0;

        /** \brief Signals the event is ready.

        If ready, wait() will not block.
        */
        virtual void Signal() = 0;

        /** \brief Associates a thread pool with this event.

        @param pool Shared pointer to the thread pool this event belongs with.
        */
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
                                               std::shared_ptr<VoidCallback> callback,
                                               const char* name);

      private:
        // Return event to wait on until the callback runs.
        virtual std::shared_ptr<Event> postTaskImpl(std::shared_ptr<VoidCallback> callback,
                                                    const char* name) = 0;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_WORKERTHREAD_H_
