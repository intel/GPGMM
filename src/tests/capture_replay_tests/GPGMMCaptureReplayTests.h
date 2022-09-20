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

#ifndef TESTS_CAPTUREREPLAYTESTS_GPGMMCAPTUREREPLAYTESTS_H_
#define TESTS_CAPTUREREPLAYTESTS_GPGMMCAPTUREREPLAYTESTS_H_

#include "tests/GPGMMTest.h"

#include <regex>
#include <string>

namespace gpgmm {
    class PlatformTime;
}

struct TraceFile {
    std::string name;
    std::string path;
};

struct CaptureReplayMemoryStats {
    uint64_t PeakUsage = 0;
    uint64_t CurrentUsage = 0;
};

enum class AllocatorProfile {
    ALLOCATOR_PROFILE_MAX_PERFORMANCE,  // Higher performance over low memory usage.
    ALLOCATOR_PROFILE_LOW_MEMORY,       // Low memory usage over higher performance.
    ALLOCATOR_PROFILE_CAPTURED,         // Use captured settings.
    ALLOCATOR_PROFILE_DEFAULT,          // Use default settings.
};

struct TestEnviromentParams {
    uint64_t Iterations = 1;  // Number of test iterations to run.
    int CaptureEventMask = 0;

    bool IsIgnoreCapsMismatchEnabled = false;  // Test device must match capture caps.
    bool IsSuballocationDisabled = false;
    bool IsNeverAllocate = false;
    bool IsPrefetchAllowed = false;
    bool IsAllocatorDisabled = false;  // Disables creation of new allocations.
    bool IsMemoryDisabled = false;     // Disables creation of captured heaps.

    AllocatorProfile AllocatorProfile =
        AllocatorProfile::ALLOCATOR_PROFILE_CAPTURED;  // Playback uses captured settings.
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

    template <class ParamType>
    static std::string CustomPrintToStringParamName(
        const ::testing::TestParamInfo<ParamType>& info) {
        std::string sanitizedTraceFileName =
            std::regex_replace(info.param.name, std::regex("[^a-zA-Z0-9]+"), "_");
        return sanitizedTraceFileName;
    }

    void RunTestLoop(const TestEnviromentParams& forceParams);
    void RunSingleTest(const TestEnviromentParams& forceParams);

  protected:
    virtual void RunTest(const TraceFile& traceFile,
                         const TestEnviromentParams& envParams,
                         uint64_t iterationIndex) = 0;

    std::unique_ptr<gpgmm::PlatformTime> mPlatformTime;
};

#define GPGMM_INSTANTIATE_CAPTURE_REPLAY_TEST(testSuiteName)                                  \
    INSTANTIATE_TEST_SUITE_P(                                                                 \
        , testSuiteName,                                                                      \
        ::testing::ValuesIn(GPGMMCaptureReplayTestEnvironment::GenerateTraceFileParams()),    \
        CaptureReplayTestWithParams::CustomPrintToStringParamName<testSuiteName::ParamType>); \
    GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(testSuiteName)

#endif  // TESTS_CAPTUREREPLAYTESTS_GPGMMCAPTUREREPLAYTESTS_H_
