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

#include "tests/GPGMMTest.h"

#include "gpgmm/common/Log.h"

#include <regex>
#include <string>

namespace gpgmm {
    class PlatformTime;
}

struct TraceFile {
    std::string name;
    std::string path;
};

struct CaptureReplayCallStats {
    double TotalCpuTime = 0;
    double PeakCpuTime = 0;
    uint64_t TotalNumOfCalls = 0;
};

struct CaptureReplayMemoryStats {
    uint64_t TotalSize = 0;
    uint64_t TotalCount = 0;
    uint64_t PeakUsage = 0;
    uint64_t CurrentUsage = 0;
};

struct TestEnviromentParams {
    uint64_t Iterations = 1;                                 // Number of test iterations to run.
    bool IsRegenerate = false;                               // Should the allocator record.
    gpgmm::LogSeverity LogLevel = gpgmm::LogSeverity::Info;  // Level of logging.
    gpgmm::LogSeverity RecordLevel = gpgmm::LogSeverity::Debug;  // Level of recording.

    bool IsStandaloneOnly = false;
    bool IsNeverAllocate = false;
};

void InitGPGMMCaptureReplayTestEnvironment(int argc, char** argv);

class GPGMMCaptureReplayTestEnvironment : public GPGMMTestEnvironment {
  public:
    GPGMMCaptureReplayTestEnvironment(int argc, char** argv);
    ~GPGMMCaptureReplayTestEnvironment() override;

    void SetUp() override;
    void TearDown() override;

    static std::vector<TraceFile> GenerateTraceFileParams();

    const TestEnviromentParams& GetParams() const;

  private:
    void PrintCaptureReplaySettings() const;

    TestEnviromentParams mParams = {};
};

class CaptureReplayTestWithParams : public testing::TestWithParam<TraceFile> {
  public:
    CaptureReplayTestWithParams();

    void LogCallStats(const std::string& name, const CaptureReplayCallStats& stats) const;
    void LogMemoryStats(const std::string& name, const CaptureReplayMemoryStats& stats) const;

    template <class ParamType>
    static std::string CustomPrintToStringParamName(
        const ::testing::TestParamInfo<ParamType>& info) {
        std::string sanitizedTraceFileName =
            std::regex_replace(info.param.name, std::regex("[^a-zA-Z0-9]+"), "_");
        return sanitizedTraceFileName;
    }

    virtual void RunTest(const TraceFile& traceFile,
                         const TestEnviromentParams& envParams,
                         uint64_t iterationIndex) = 0;

    void RunTestLoop();

  protected:
    std::unique_ptr<gpgmm::PlatformTime> mPlatformTime;
};

#define GPGMM_INSTANTIATE_CAPTURE_REPLAY_TEST(testSuiteName)                                  \
    INSTANTIATE_TEST_SUITE_P(                                                                 \
        , testSuiteName,                                                                      \
        ::testing::ValuesIn(GPGMMCaptureReplayTestEnvironment::GenerateTraceFileParams()),    \
        CaptureReplayTestWithParams::CustomPrintToStringParamName<testSuiteName::ParamType>); \
    GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(testSuiteName)

#endif  // TESTS_CAPTUREREPLAYTESTS_GPGMMCAPTUREREPLAYTESTS_H_
