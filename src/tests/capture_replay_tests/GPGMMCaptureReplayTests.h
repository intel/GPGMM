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

#ifndef TESTS_CAPTUREREPLAYTESTS_GPGMMCAPTUREREPLAYTESTS_H_
#define TESTS_CAPTUREREPLAYTESTS_GPGMMCAPTUREREPLAYTESTS_H_

#include "src/tests/GPGMMTest.h"

#include <regex>
#include <string>

struct TraceFile {
    std::string name;
    std::string path;
};

void InitGPGMMCaptureReplayTestEnvironment(int argc, char** argv);

class GPGMMCaptureReplayTestEnvironment : public GPGMMTestEnvironment {
  public:
    GPGMMCaptureReplayTestEnvironment(int argc, char** argv);
    ~GPGMMCaptureReplayTestEnvironment() override;

    static std::vector<TraceFile> GenerateTraceFileParams();

    void SetUp() override;
    void TearDown() override;
};

class CaptureReplyTestWithParams : public testing::TestWithParam<TraceFile> {
  public:
    template <class ParamType>
    static std::string CustomPrintToStringParamName(
        const ::testing::TestParamInfo<ParamType>& info) {
        std::string sanitizedTraceFileName =
            std::regex_replace(info.param.name, std::regex("[^a-zA-Z0-9]+"), "_");
        return sanitizedTraceFileName;
    }
};

#define GPGMM_INSTANTIATE_CAPTURE_REPLAY_TEST(testSuiteName)                                 \
    INSTANTIATE_TEST_SUITE_P(                                                                \
        , testSuiteName,                                                                     \
        ::testing::ValuesIn(GPGMMCaptureReplayTestEnvironment::GenerateTraceFileParams()),   \
        CaptureReplyTestWithParams::CustomPrintToStringParamName<testSuiteName::ParamType>); \
    GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(testSuiteName)

#endif  // TESTS_CAPTUREREPLAYTESTS_GPGMMCAPTUREREPLAYTESTS_H_
