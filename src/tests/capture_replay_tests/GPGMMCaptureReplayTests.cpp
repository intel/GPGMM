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

#include "src/tests/capture_replay_tests/GPGMMCaptureReplayTests.h"

#include "src/common/Log.h"
#include "src/common/PlatformTime.h"
#include "src/common/SystemUtils.h"

#include <json/json.h>
#include <fstream>
#include <vector>

static const std::string kTraceIndex = GPGMM_CAPTURE_REPLAY_TESTS_TRACE_INDEX;

namespace {

    GPGMMCaptureReplayTestEnvironment* gTestEnv = nullptr;

}  // namespace

void InitGPGMMCaptureReplayTestEnvironment(int argc, char** argv) {
    gTestEnv = new GPGMMCaptureReplayTestEnvironment(argc, argv);
    GPGMMTestEnvironment::SetEnvironment(gTestEnv);
    testing::AddGlobalTestEnvironment(gTestEnv);
}

GPGMMCaptureReplayTestEnvironment::GPGMMCaptureReplayTestEnvironment(int argc, char** argv)
    : GPGMMTestEnvironment(argc, argv) {
    for (int i = 1; i < argc; ++i) {
        constexpr const char kIterationArg[] = "--iterations=";
        size_t arglen = sizeof(kIterationArg) - 1;
        if (strncmp(argv[i], kIterationArg, arglen) == 0) {
            const char* iterations = argv[i] + arglen;
            mIterations = strtoul(iterations, nullptr, 0);
            continue;
        }

        if (strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0) {
            gpgmm::InfoLog() << "Additional Flags:"
                             << " [--iterations=X]\n"
                             << " --iterations: Number of times to replay the capture.\n";
            continue;
        }
    }
}

GPGMMCaptureReplayTestEnvironment::~GPGMMCaptureReplayTestEnvironment() = default;

void GPGMMCaptureReplayTestEnvironment::SetUp() {
    GPGMMTestEnvironment::SetUp();
    // TODO
}

void GPGMMCaptureReplayTestEnvironment::TearDown() {
    // TODO
    GPGMMTestEnvironment::TearDown();
}

// static
std::vector<TraceFile> GPGMMCaptureReplayTestEnvironment::GenerateTraceFileParams() {
    Json::Value root;
    Json::Reader reader;
    std::ifstream traceIndex(kTraceIndex, std::ifstream::binary);
    bool result = reader.parse(traceIndex, root, false);
    if (!result) {
        std::cout << "Unable to parse: " << kTraceIndex << "." << std::endl;
        return {};
    }

    const Json::Value& traceFilesJson = root["traceFiles"];

    std::vector<TraceFile> traceFiles;
    for (Json::Value::ArrayIndex traceFileIndex = 0; traceFileIndex < traceFilesJson.size();
         traceFileIndex++) {
        const Json::Value traceFileJson = traceFilesJson[traceFileIndex];
        traceFiles.push_back({traceFileJson["name"].asString(), traceFileJson["path"].asString()});
    }

    return traceFiles;
}

uint64_t GPGMMCaptureReplayTestEnvironment::GetIterations() const {
    return mIterations;
}

CaptureReplayTestWithParams::CaptureReplayTestWithParams()
    : mPlatformTime(gpgmm::CreatePlatformTime()) {
}

void CaptureReplayTestWithParams::RunTestLoop() {
    for (uint32_t i = 0; i < gTestEnv->GetIterations(); i++) {
        RunTest(GetParam());
    }
}

void CaptureReplayTestWithParams::LogCallStats(const std::string& name,
                                               const CaptureReplayCallStats& stats) const {
    const double avgCpuTimePerCall =
        (stats.TotalCpuTime * 1e3) / ((stats.TotalNumOfCalls == 0) ? 1 : stats.TotalNumOfCalls);
    gpgmm::InfoLog() << name << " avg call time (ms): " << avgCpuTimePerCall;
}

void CaptureReplayTestWithParams::LogMemoryStats(const std::string& name,
                                                 const CaptureReplayMemoryStats& stats) const {
    gpgmm::InfoLog() << "total " << name
                     << " size (bytes): " << stats.TotalSize / gTestEnv->GetIterations();

    if (stats.PeakUsage > 0) {
        gpgmm::InfoLog() << "peak " << name << " usage (bytes): " << stats.PeakUsage;
    }

    gpgmm::InfoLog() << "total " << name
                     << " count: " << stats.TotalCount / gTestEnv->GetIterations();
}
