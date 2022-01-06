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

#include "src/common/Assert.h"
#include "src/common/PlatformTime.h"
#include "src/common/SystemUtils.h"

#include <json/json.h>
#include <fstream>
#include <vector>

static const std::string kTraceIndex = GPGMM_CAPTURE_REPLAY_TESTS_TRACE_INDEX;

static TraceFile gSingleTraceFile = {"SingleTrace", ""};

namespace {

    GPGMMCaptureReplayTestEnvironment* gTestEnv = nullptr;

    std::string LogSeverityToString(const gpgmm::LogSeverity& severity) {
        switch (severity) {
            case gpgmm::LogSeverity::Debug:
                return "DEBUG";
            case gpgmm::LogSeverity::Info:
                return "INFO";
            case gpgmm::LogSeverity::Warning:
                return "WARN";
            case gpgmm::LogSeverity::Error:
                return "ERROR";
            default:
                UNREACHABLE();
                return "";
        }
    }

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
            mParams.Iterations = strtoul(iterations, nullptr, 0);
            continue;
        }

        if (strcmp("--standalone-only", argv[i]) == 0) {
            mParams.IsStandaloneOnly = true;
            continue;
        }

        if (strcmp("--regenerate", argv[i]) == 0) {
            mParams.IsRegenerate = true;
            continue;
        }

        constexpr const char kRecordLevel[] = "--record-level";
        arglen = sizeof(kRecordLevel) - 1;
        if (strncmp(argv[i], kRecordLevel, arglen) == 0) {
            const char* level = argv[i] + arglen;
            if (level[0] != '\0') {
                if (strcmp(level, "=DEBUG") == 0) {
                    mParams.RecordLevel = gpgmm::LogSeverity::Debug;
                } else if (strcmp(level, "=INFO") == 0) {
                    mParams.RecordLevel = gpgmm::LogSeverity::Info;
                } else if (strcmp(level, "=WARN") == 0) {
                    mParams.RecordLevel = gpgmm::LogSeverity::Warning;
                } else if (strcmp(level, "=ERROR") == 0) {
                    mParams.RecordLevel = gpgmm::LogSeverity::Error;
                } else {
                    gpgmm::ErrorLog() << "Invalid record log level " << level;
                    UNREACHABLE();
                }
            } else {
                mParams.RecordLevel = gpgmm::LogSeverity::Info;
            }
            continue;
        }

        constexpr const char kLogLevel[] = "--log-level";
        arglen = sizeof(kLogLevel) - 1;
        if (strncmp(argv[i], kLogLevel, arglen) == 0) {
            const char* level = argv[i] + arglen;
            if (level[0] != '\0') {
                if (strcmp(level, "=DEBUG") == 0) {
                    mParams.LogLevel = gpgmm::LogSeverity::Debug;
                } else if (strcmp(level, "=INFO") == 0) {
                    mParams.LogLevel = gpgmm::LogSeverity::Info;
                } else if (strcmp(level, "=WARN") == 0) {
                    mParams.LogLevel = gpgmm::LogSeverity::Warning;
                } else if (strcmp(level, "=ERROR") == 0) {
                    mParams.LogLevel = gpgmm::LogSeverity::Error;
                } else {
                    gpgmm::ErrorLog() << "Invalid log message level " << level;
                    UNREACHABLE();
                }
            } else {
                mParams.LogLevel = gpgmm::LogSeverity::Warning;
            }
            continue;
        }

        constexpr const char kPlaybackFile[] = "--playback-file=";
        arglen = sizeof(kPlaybackFile) - 1;
        if (strncmp(argv[i], kPlaybackFile, arglen) == 0) {
            const char* path = argv[i] + arglen;
            if (path[0] != '\0') {
                gSingleTraceFile.path = std::string(path);
            } else {
                gpgmm::ErrorLog() << "Invalid playback file path " << path;
                UNREACHABLE();
            }
            continue;
        }

        if (strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0) {
            gpgmm::InfoLog() << "Additional Flags:"
                             << " [--iterations=X]\n"
                             << " --iterations: Number of times to playback the capture.\n"
                             << " --standalone-only: Disable sub-allocation.\n"
                             << " --record-level=[DEBUG|INFO|WARN|ERROR]: Message severity "
                                "level to record logs.\n"
                             << " --log-level=[DEBUG|INFO|WARN|ERROR]: Message severity "
                                "level for logs.\n"
                             << " --regenerate: Capture again upon playback.\n"
                             << " --playback-file: Path to single capture file to playback.\n";
            continue;
        }
    }

    PrintCaptureReplaySettings();
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

void GPGMMCaptureReplayTestEnvironment::PrintCaptureReplaySettings() const {
    std::cout << "Playback environment settings\n"
                 "------------------------\n"
              << "Iterations per test: " << mParams.Iterations << "\n"
              << "Standalone allocations only: " << (mParams.IsStandaloneOnly ? "true" : "false")
              << "\n"
              << "Regenerate on playback: " << (mParams.IsRegenerate ? "true" : "false") << "\n"
              << "Record level: " << LogSeverityToString(mParams.RecordLevel) << "\n"
              << "Log level: " << LogSeverityToString(mParams.LogLevel) << "\n"
              << std::endl;
}

// static
std::vector<TraceFile> GPGMMCaptureReplayTestEnvironment::GenerateTraceFileParams() {
    // Playback only the trace file specified in command-line.
    if (!gSingleTraceFile.path.empty()) {
        return {gSingleTraceFile};
    }

    Json::Value root;
    Json::Reader reader;
    std::ifstream traceIndex(kTraceIndex, std::ifstream::binary);
    bool result = reader.parse(traceIndex, root, false);
    if (!result) {
        gpgmm::ErrorLog() << "Unable to parse: " << kTraceIndex;
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

const TestEnviromentParams& GPGMMCaptureReplayTestEnvironment::GetParams() const {
    return mParams;
}

// CaptureReplayTestWithParams

CaptureReplayTestWithParams::CaptureReplayTestWithParams()
    : mPlatformTime(gpgmm::CreatePlatformTime()) {
}

void CaptureReplayTestWithParams::RunTestLoop() {
    const TestEnviromentParams& envParams = gTestEnv->GetParams();
    for (uint32_t i = 0; i < envParams.Iterations; i++) {
        RunTest(GetParam(), envParams);
    }
}

void CaptureReplayTestWithParams::LogCallStats(const std::string& name,
                                               const CaptureReplayCallStats& stats) const {
    const double avgCpuTimePerCall =
        (stats.TotalCpuTime * 1e3) / ((stats.TotalNumOfCalls == 0) ? 1 : stats.TotalNumOfCalls);
    gpgmm::InfoLog() << name << " avg cpu time (ms): " << avgCpuTimePerCall;
}

void CaptureReplayTestWithParams::LogMemoryStats(const std::string& name,
                                                 const CaptureReplayMemoryStats& stats) const {
    gpgmm::InfoLog() << name << " total "
                     << "size (bytes): " << stats.TotalSize / gTestEnv->GetParams().Iterations;

    if (stats.PeakUsage > 0) {
        gpgmm::InfoLog() << name << " peak usage (bytes): " << stats.PeakUsage;
    }

    gpgmm::InfoLog() << name << " total "
                     << "count: " << stats.TotalCount / gTestEnv->GetParams().Iterations;
}
