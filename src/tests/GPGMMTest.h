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

#ifndef TESTS_GPGMM_TEST_H_
#define TESTS_GPGMM_TEST_H_

#include "gtest/gtest.h"

class GPGMMTestBase {
  protected:
    virtual ~GPGMMTestBase();

    void SetUp();
    void TearDown();

    bool IsDeviceLeakChecksEnabled() const;
};

void InitGPGMMEnd2EndTestEnvironment(int argc, char** argv);

class GPGMMTestEnvironment : public testing::Environment {
  public:
    GPGMMTestEnvironment(int argc, char** argv);

    static void SetEnvironment(GPGMMTestEnvironment* env);

    void SetUp() override;

    bool IsDeviceLeakChecksEnabled() const;

  private:
    void PrintTestEnviromentSettings() const;

    bool mEnableCheckDeviceLeaks = false;
};

#endif  // TESTS_GPGMM_TEST_H_
