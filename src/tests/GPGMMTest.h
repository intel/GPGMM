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

#ifndef TESTS_GPGMMTEST_H_
#define TESTS_GPGMMTEST_H_

#include <gtest/gtest.h>

#include "gpgmm/common/Log.h"
#include "gpgmm/common/PlatformDebug.h"

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

#define GPGMM_TEST_MEMORY_LEAK_END()                        \
    do {                                                    \
        EXPECT_FALSE(GetDebugPlatform()->EndMemoryCheck()); \
    } while (0)

namespace gpgmm {
    class DebugPlatform;
}  // namespace gpgmm

class GPGMMTestBase {
  protected:
    virtual ~GPGMMTestBase();

    void SetUp();
    void TearDown();

    gpgmm::DebugPlatform* GetDebugPlatform();
};

void InitGPGMMEnd2EndTestEnvironment(int argc, char** argv);

class GPGMMTestEnvironment : public testing::Environment {
  public:
    GPGMMTestEnvironment() = default;

    static void SetEnvironment(GPGMMTestEnvironment* env);

    void SetUp() override;
};

#endif  // TESTS_GPGMMTEST_H_
