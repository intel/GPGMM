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

#ifndef TESTS_GPGMMTEST_H_
#define TESTS_GPGMMTEST_H_

#include <gtest/gtest.h>

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/utils/Log.h"
#include "gpgmm/utils/PlatformDebug.h"

#include <vector>

#define GPGMM_SKIP_TEST_IF(expr)                            \
    do {                                                    \
        if (expr) {                                         \
            gpgmm::InfoLog() << "Test skipped: " #expr "."; \
            GTEST_SKIP();                                   \
            return;                                         \
        }                                                   \
    } while (0)

#define GPGMM_TEST_MEMORY_LEAK_START()          \
    do {                                        \
        GetDebugPlatform()->StartMemoryCheck(); \
    } while (0)

// TearDown must be called before the end check since process-wide memory
// created by the test needs a chance to release to avoid become a false-positive.
#define GPGMM_TEST_MEMORY_LEAK_END()                        \
    do {                                                    \
        TearDown();                                         \
        EXPECT_FALSE(GetDebugPlatform()->EndMemoryCheck()); \
    } while (0)

namespace gpgmm {
    class DebugPlatform;
}  // namespace gpgmm

struct MEMORY_ALLOCATION_EXPECT {
    uint64_t size;
    uint64_t alignment;
    bool succeeds;
};

class GPGMMTestBase {
  protected:
    virtual ~GPGMMTestBase();

    void SetUp();
    void TearDown();

    gpgmm::DebugPlatform* GetDebugPlatform();

    bool IsDumpEventsEnabled() const;
    gpgmm::LogSeverity GetLogLevel() const;

    static std::vector<MEMORY_ALLOCATION_EXPECT> GenerateTestAllocations(uint64_t alignment);
};

void InitGPGMMEnd2EndTestEnvironment(int argc, char** argv);

class GPGMMTestEnvironment : public testing::Environment {
  public:
    GPGMMTestEnvironment(int argc, char** argv);

    static void SetEnvironment(GPGMMTestEnvironment* env);

    void SetUp() override;

    bool IsDumpEventsEnabled() const;
    bool IsReportMemoryLeaksEnabled() const;
    gpgmm::LogSeverity GetLogLevel() const;

  private:
    bool mIsDumpEventsEnabled = false;
    bool mIsReportMemoryLeaksEnabled = false;
    gpgmm::LogSeverity mLogLevel;  // Initialized by Setup().
};

#endif  // TESTS_GPGMMTEST_H_
