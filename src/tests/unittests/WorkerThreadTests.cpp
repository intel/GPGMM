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

#include <gtest/gtest.h>

#include "gpgmm/common/WorkerThread.h"

using namespace gpgmm;

#include <vector>

class DummyTask : public VoidCallback {
  public:
    void operator()() override {
        mIsTaskCompleted = true;
    }

    bool mIsTaskCompleted = false;
};

TEST(WorkerThreadTests, SingleAsyncTask) {
    std::shared_ptr<ThreadPool> pool(ThreadPool::Create());
    ASSERT_NE(pool, nullptr);

    std::shared_ptr<DummyTask> task = std::make_shared<DummyTask>();
    ASSERT_NE(task, nullptr);

    std::shared_ptr<Event> event = ThreadPool::PostTask(pool, task);
    ASSERT_NE(event, nullptr);

    event->Wait();

    ASSERT_TRUE(task->mIsTaskCompleted);
}

TEST(WorkerThreadTests, ManyTaskWait) {
    std::shared_ptr<ThreadPool> pool(ThreadPool::Create());
    ASSERT_NE(pool, nullptr);

    constexpr uint32_t kTaskCount = 10000u;

    std::vector<std::pair<std::shared_ptr<Event>, std::shared_ptr<DummyTask>>> tasks;
    for (uint32_t i = 0; i < kTaskCount; i++) {
        std::shared_ptr<DummyTask> task = std::make_shared<DummyTask>();
        ASSERT_NE(task, nullptr);

        tasks.push_back(std::make_pair(ThreadPool::PostTask(pool, task), task));
    }

    for (auto& task : tasks) {
        task.first->Wait();
        ASSERT_TRUE(task.second->mIsTaskCompleted);
    }
}

TEST(WorkerThreadTests, ManyTaskExit) {
    std::shared_ptr<ThreadPool> pool(ThreadPool::Create());
    ASSERT_NE(pool, nullptr);

    constexpr uint32_t kTaskCount = 10000u;

    std::vector<std::pair<std::shared_ptr<Event>, std::shared_ptr<DummyTask>>> tasks;
    for (uint32_t i = 0; i < kTaskCount; i++) {
        std::shared_ptr<DummyTask> task = std::make_shared<DummyTask>();
        ASSERT_NE(pool, nullptr);

        tasks.push_back(std::make_pair(ThreadPool::PostTask(pool, task), task));
    }

    pool.reset();
}
