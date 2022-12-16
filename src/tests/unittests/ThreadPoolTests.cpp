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

#include <gtest/gtest.h>

#include "gpgmm/common/ThreadPool.h"
#include "gpgmm/utils/Assert.h"
#include "tests/GPGMMTest.h"

#include <thread>
#include <vector>

using namespace gpgmm;

class Task : public VoidCallback {
  public:
    void operator()() {
        ASSERT(true);
    }
};

TEST(ThreadPoolTests, Create) {
    std::shared_ptr<ThreadPool> pool =
        ThreadPool::Create(/*minThreadCount*/ 0, /*maxThreadCount*/ 0);
    EXPECT_NE(pool, nullptr);
    EXPECT_EQ(pool->GetCurrentThreadCount(), 0u);
    EXPECT_EQ(pool->GetMaxThreadCount(), 0u);
}

TEST(ThreadPoolTests, SingleTask) {
    std::shared_ptr<ThreadPool> pool =
        ThreadPool::Create(/*minThreadCount*/ 0, /*maxThreadCount*/ 1);
    EXPECT_NE(pool, nullptr);

    auto event = ThreadPool::PostTask(pool, std::make_shared<Task>());
    EXPECT_NE(event, nullptr);
    EXPECT_EQ(pool->GetCurrentThreadCount(), 1u);
    EXPECT_EQ(pool->GetMaxThreadCount(), 1u);

    event->Wait();
    EXPECT_TRUE(event->IsSignaled());

    pool->Shutdown();
    EXPECT_EQ(pool->GetCurrentThreadCount(), 0u);
}

TEST(ThreadPoolTests, ManyTasks) {
    std::shared_ptr<ThreadPool> pool =
        ThreadPool::Create(/*minThreadCount*/ 0, /*maxThreadCount*/ 2);

    constexpr uint32_t kMaxTaskCount = 10000u;
    for (uint32_t numOfTasks = 0; numOfTasks < kMaxTaskCount; numOfTasks++) {
        std::shared_ptr<Task> task = std::make_shared<Task>();
        EXPECT_NE(ThreadPool::PostTask(pool, task), nullptr);
    }

    EXPECT_GT(pool->GetCurrentThreadCount(), 0u);
    EXPECT_EQ(pool->GetMaxThreadCount(), 2u);

    pool->Shutdown();
    EXPECT_EQ(pool->GetCurrentThreadCount(), 0u);
}
