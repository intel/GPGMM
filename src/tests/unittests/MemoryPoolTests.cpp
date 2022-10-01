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

#include "gpgmm/common/LIFOMemoryPool.h"
#include "tests/DummyMemoryAllocator.h"

using namespace gpgmm;

static uint64_t kDefaultMemorySize = 128u;

class MemoryPoolTests : public testing::Test {
  public:
    MemoryAllocationRequest CreateBasicRequest(uint64_t size) {
        MemoryAllocationRequest request = {};
        request.SizeInBytes = size;
        request.Alignment = 1;
        return request;
    }
};

class LIFOMemoryPoolTests : public MemoryPoolTests {};

TEST_F(LIFOMemoryPoolTests, SingleAllocation) {
    DummyMemoryAllocator allocator;
    LIFOMemoryPool pool(kDefaultMemorySize);
    EXPECT_EQ(pool.GetStats().SizeInBytes, 0u);

    EXPECT_EQ(pool.ReleasePool(), 0u);
    EXPECT_EQ(pool.GetStats().SizeInBytes, 0u);

    pool.ReturnToPool(*allocator.TryAllocateMemory(CreateBasicRequest(kDefaultMemorySize)));
    EXPECT_EQ(pool.GetStats().SizeInBytes, kDefaultMemorySize);
    EXPECT_EQ(pool.GetPoolSize(), 1u);

    pool.ReturnToPool(pool.AcquireFromPool());
    EXPECT_EQ(pool.GetStats().SizeInBytes, kDefaultMemorySize);
    EXPECT_EQ(pool.GetPoolSize(), 1u);

    EXPECT_EQ(pool.ReleasePool(kDefaultMemorySize), kDefaultMemorySize);
    EXPECT_EQ(pool.GetStats().SizeInBytes, 0u);
    EXPECT_EQ(pool.GetPoolSize(), 0u);

    EXPECT_EQ(pool.ReleasePool(), 0u);
    EXPECT_EQ(pool.GetStats().SizeInBytes, 0u);
    EXPECT_EQ(pool.GetPoolSize(), 0u);
}

TEST_F(LIFOMemoryPoolTests, MultipleAllocations) {
    DummyMemoryAllocator allocator;
    LIFOMemoryPool pool(kDefaultMemorySize);
    EXPECT_EQ(pool.GetStats().SizeInBytes, 0u);
    EXPECT_EQ(pool.GetPoolSize(), 0u);

    constexpr uint64_t kPoolSize = 64;
    while (pool.GetPoolSize() < kPoolSize) {
        pool.ReturnToPool(*allocator.TryAllocateMemory(CreateBasicRequest(kDefaultMemorySize)));
    }

    EXPECT_EQ(pool.GetStats().SizeInBytes, kDefaultMemorySize * kPoolSize);
    EXPECT_EQ(pool.GetPoolSize(), kPoolSize);

    // Release half of the pool.
    EXPECT_EQ(pool.ReleasePool(kDefaultMemorySize * kPoolSize / 2),
              kDefaultMemorySize * kPoolSize / 2);
    EXPECT_EQ(pool.GetPoolSize(), kPoolSize / 2);

    // Release the other half.
    EXPECT_EQ(pool.ReleasePool(), kDefaultMemorySize * kPoolSize / 2);
    EXPECT_EQ(pool.GetStats().SizeInBytes, 0u);
    EXPECT_EQ(pool.GetPoolSize(), 0u);
}
