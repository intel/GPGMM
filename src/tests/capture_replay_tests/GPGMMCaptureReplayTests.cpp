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

#include "tests/capture_replay_tests/GPGMMCaptureReplayTests.h"

#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/PlatformTime.h"
#include "gpgmm/utils/PlatformUtils.h"

#include <json/json.h>
#include <fstream>
#include <vector>

static const std::string kTraceIndex = GPGMM_CAPTURE_REPLAY_TESTS_TRACE_INDEX;

static std::string gSingleTraceFilePath = "";  // Always empty unless set by command-line option.

namespace {

    GPGMMCaptureReplayTestEnvironment* gTestEnv = nullptr;

    std::string AllocatorProfileToString(const AllocatorProfile& profile) {
        switch (profile) {
            case AllocatorProfile::ALLOCATOR_PROFILE_MAX_PERFORMANCE:
                return "Max Performance";
            case AllocatorProfile::ALLOCATOR_PROFILE_LOW_MEMORY:
                return "Low Memory";
            case AllocatorProfile::ALLOCATOR_PROFILE_CAPTURED:
                return "Captured";
            case AllocatorProfile::ALLOCATOR_PROFILE_DEFAULT:
                return "Default";
            default:
                UNREACHABLE();
                return "";
        }
    }

    AllocatorProfile StringToAllocatorProfile(std::string profile) {
        if (profile == "MAXPERF" || profile == "PERF" || profile == "MAX") {
            return AllocatorProfile::ALLOCATOR_PROFILE_MAX_PERFORMANCE;
        } else if (profile == "LOWMEM" || profile == "LOW" || profile == "MEM") {
            return AllocatorProfile::ALLOCATOR_PROFILE_LOW_MEMORY;
        } else if (profile == "DEFAULT" || profile == "NONE") {
            return AllocatorProfile::ALLOCATOR_PROFILE_DEFAULT;
        } else {
            return AllocatorProfile::ALLOCATOR_PROFILE_CAPTURED;
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

        constexpr const char kCaptureMask[] = "--capture-mask=";
        arglen = sizeof(kCaptureMask) - 1;
        if (strncmp(argv[i], kCaptureMask, arglen) == 0) {
            const char* mask = argv[i] + arglen;
            mParams.CaptureEventMask = strtoul(mask, nullptr, 0);
            continue;
        }

        if (strcmp("--ignore-caps-mismatch", argv[i]) == 0) {
            mParams.IsIgnoreCapsMismatchEnabled = true;
            continue;
        }

        if (strcmp("--disable-suballocation", argv[i]) == 0) {
            mParams.IsSuballocationDisabled = true;
            continue;
        }

        if (strcmp("--disable-allocation", argv[i]) == 0) {
            mParams.IsAllocatorDisabled = true;
            continue;
        }

        if (strcmp("--disable-memory", argv[i]) == 0) {
            mParams.IsMemoryDisabled = true;
            continue;
        }

        constexpr const char kPlaybackFile[] = "--playback-file=";
        arglen = sizeof(kPlaybackFile) - 1;
        if (strncmp(argv[i], kPlaybackFile, arglen) == 0) {
            const char* path = argv[i] + arglen;
            if (path[0] != '\0') {
                gSingleTraceFilePath = std::string(path);
            } else {
                gpgmm::ErrorLog() << "Invalid playback file " << path << ".\n";
                UNREACHABLE();
            }
            continue;
        }

        constexpr const char kProfile[] = "--profile=";
        arglen = sizeof(kProfile) - 1;
        if (strncmp(argv[i], kProfile, arglen) == 0) {
            const char* profile = argv[i] + arglen;
            if (profile[0] != '\0') {
                mParams.AllocatorProfile = StringToAllocatorProfile(std::string(profile));
            } else {
                gpgmm::ErrorLog() << "Invalid profile " << profile << ".\n";
                UNREACHABLE();
            }
            continue;
        }

        if (strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0) {
            gpgmm::InfoLog()
                << "Playback options:"
                << " [--iterations=X]\n"
                << " --iterations: Number of times to run playback.\n"
                << " --capture-mask: Event mask to record during capture.\n"
                << " --playback-file: Path to captured file to playback.\n"
                << " --same-caps: Captured device must be compatible with playback device.\n"
                << " --profile=[MAXPERF|LOWMEM|CAPTURED|DEFAULT]: Profile to apply.\n"
                << " --disable-allocator: Disables allocator playback.\n"
                << " --disable-memory: Disables playback of memory from capture.\n";
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
    gpgmm::InfoLog() << "Playback settings\n"
                        "-----------------\n"
                     << "Iterations per test: " << mParams.Iterations << "\n";

    gpgmm::InfoLog() << "Experiment settings\n"
                        "-------------------\n"
                     << "Profile: " << AllocatorProfileToString(mParams.AllocatorProfile) << "\n";
}

// static
std::vector<TraceFile> GPGMMCaptureReplayTestEnvironment::GenerateTraceFileParams() {
    // Playback only the file specified in command-line option.
    if (!gSingleTraceFilePath.empty()) {
        return {TraceFile{"SingleTrace", gSingleTraceFilePath}};
    }

    // Playback all files contained in traces folder.
    Json::Value root;
    Json::Reader reader;
    std::ifstream traceIndex(kTraceIndex, std::ifstream::binary);
    bool result = reader.parse(traceIndex, root, false);
    if (!result) {
        gpgmm::ErrorLog() << "Unable to parse: " << kTraceIndex << ".\n";
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
void CaptureReplayTestWithParams::RunSingleTest(const TestEnviromentParams& forceParams) {
    return RunTestLoop(forceParams);
}

void CaptureReplayTestWithParams::RunTestLoop(const TestEnviromentParams& forceParams) {
    TestEnviromentParams envParams = gTestEnv->GetParams();

    if (forceParams.CaptureEventMask != envParams.CaptureEventMask) {
        envParams.CaptureEventMask |= forceParams.CaptureEventMask;
    }

    if (forceParams.IsIgnoreCapsMismatchEnabled != envParams.IsIgnoreCapsMismatchEnabled) {
        envParams.IsIgnoreCapsMismatchEnabled |= forceParams.IsIgnoreCapsMismatchEnabled;
    }

    if (forceParams.Iterations != envParams.Iterations) {
        envParams.Iterations = forceParams.Iterations;
    }

    if (forceParams.IsPrefetchAllowed != envParams.IsPrefetchAllowed) {
        envParams.IsPrefetchAllowed |= forceParams.IsPrefetchAllowed;
    }

    if (forceParams.IsSuballocationDisabled != envParams.IsSuballocationDisabled) {
        envParams.IsSuballocationDisabled |= forceParams.IsSuballocationDisabled;
    }

    if (forceParams.IsNeverAllocate != envParams.IsNeverAllocate) {
        envParams.IsNeverAllocate |= forceParams.IsNeverAllocate;
    }

    for (uint32_t i = 0; i < envParams.Iterations; i++) {
        RunTest(GetParam(), envParams, i);
    }
}
