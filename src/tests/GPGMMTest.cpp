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

#include "tests/GPGMMTest.h"

#include "gpgmm/common/SizeClass.h"

#include <iostream>

static GPGMMTestEnvironment* gTestEnv = nullptr;

static std::unique_ptr<gpgmm::DebugPlatform> mDebugPlatform(gpgmm::CreateDebugPlatform());

GPGMMTestBase::~GPGMMTestBase() {
}

void GPGMMTestBase::SetUp() {
    if (mDebugPlatform != nullptr) {
        if (gTestEnv->IsReportMemoryLeaksEnabled()) {
            mDebugPlatform->ReportMemoryLeaks();
        }
    }
}

void GPGMMTestBase::TearDown() {
    gpgmm::TaskScheduler::ReleaseInstanceForTesting();
}

gpgmm::DebugPlatform* GPGMMTestBase::GetDebugPlatform() {
    return mDebugPlatform.get();
}

bool GPGMMTestBase::IsDumpEventsEnabled() const {
    return gTestEnv->IsDumpEventsEnabled();
}

gpgmm::MessageSeverity GPGMMTestBase::GetLogLevel() const {
    return gTestEnv->GetLogLevel();
}

// static
std::vector<MEMORY_ALLOCATION_EXPECT> GPGMMTestBase::GenerateTestAllocations(uint64_t alignment) {
    return {
        // Edge-case fails.
        {0, 0, false},
        {0, 1, false},
        {gpgmm::kInvalidSize, 1, false},

        // Edge-case pass.
        {1, gpgmm::kInvalidSize, true},
        {alignment - 1, 1, true},
        {alignment + 1, 1, true},
        {1, alignment - 1, true},
        {1, alignment + 1, true},

        // Common small sizes, likely sub-allocated.
        {256, alignment, true},
        {GPGMM_KB_TO_BYTES(1), alignment, true},
        {GPGMM_KB_TO_BYTES(4), alignment, true},

        // Common large sizes, likely standalone.
        {GPGMM_MB_TO_BYTES(16), 0, true},
        {GPGMM_MB_TO_BYTES(64), 0, true},

        // Mixed sizes, any method.
        {GPGMM_KB_TO_BYTES(1), 1, true},
        {GPGMM_MB_TO_BYTES(64), 0, true},
        {GPGMM_KB_TO_BYTES(1), 1, true},
        {GPGMM_MB_TO_BYTES(64), 0, true},
        {GPGMM_KB_TO_BYTES(1), 1, true},
        {GPGMM_MB_TO_BYTES(64), 0, true},

        // Increasing sizes, any method.
        {alignment * 1, 0, true},
        {alignment * 2, 0, true},
        {alignment * 4, 0, true},
        {alignment * 8, 0, true},
        {alignment * 16, 0, true},
        {alignment * 32, 0, true},
        {alignment * 64, 0, true},
        {alignment * 128, 0, true},
        {alignment * 256, 0, true},
        {alignment * 512, 0, true},
        {alignment * 1024, 0, true},
    };
}

void InitGPGMMEnd2EndTestEnvironment(int argc, char** argv) {
    gTestEnv = new GPGMMTestEnvironment(argc, argv);
    testing::AddGlobalTestEnvironment(gTestEnv);
}

// GPGMMTestEnvironment

GPGMMTestEnvironment::GPGMMTestEnvironment(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp("--dump", argv[i]) == 0) {
            mIsDumpEventsEnabled = true;
            continue;
        }

        if (strcmp("--no-leaks", argv[i]) == 0) {
            mIsReportMemoryLeaksEnabled = true;
            continue;
        }

        constexpr const char kDebugMode[] = "--debug";
        size_t arglen = sizeof(kDebugMode) - 1;
        if (strncmp(argv[i], kDebugMode, arglen) == 0) {
            mLogLevel = gpgmm::MessageSeverity::kDebug;
            continue;
        }

        constexpr const char kLogLevel[] = "--log-level";
        arglen = sizeof(kLogLevel) - 1;
        if (strncmp(argv[i], kLogLevel, arglen) == 0) {
            const char* level = argv[i] + arglen;
            if (level[0] != '\0') {
                if (strcmp(level, "=DEBUG") == 0) {
                    mLogLevel = gpgmm::MessageSeverity::kDebug;
                } else if (strcmp(level, "=INFO") == 0) {
                    mLogLevel = gpgmm::MessageSeverity::kInfo;
                } else if (strcmp(level, "=WARN") == 0) {
                    mLogLevel = gpgmm::MessageSeverity::kWarning;
                } else if (strcmp(level, "=ERROR") == 0) {
                    mLogLevel = gpgmm::MessageSeverity::kError;
                } else {
                    gpgmm::ErrorLog() << "Invalid log level " << level << ".\n";
                    UNREACHABLE();
                }
            } else {
                mLogLevel = gpgmm::MessageSeverity::kWarning;
            }
            continue;
        }

        if (strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0) {
            gpgmm::InfoLog() << "Global options:\n"
                             << " --dump: Record all events to disk.\n"
                             << " --debug: Shortcut for --log-level=DEBUG.\n"
                             << " --log-level=[DEBUG|INFO|WARN|ERROR]: Log "
                                "level for log messages.\n"
                             << " --no-leaks: Report memory leaks.\n";
            continue;
        }
    }
}

// static
void GPGMMTestEnvironment::SetEnvironment(GPGMMTestEnvironment* env) {
    gTestEnv = env;
}

void GPGMMTestEnvironment::SetUp() {
    mLogLevel = gpgmm::GetLogLevel();
}

bool GPGMMTestEnvironment::IsDumpEventsEnabled() const {
    return mIsDumpEventsEnabled;
}

bool GPGMMTestEnvironment::IsReportMemoryLeaksEnabled() const {
    return mIsReportMemoryLeaksEnabled;
}

gpgmm::MessageSeverity GPGMMTestEnvironment::GetLogLevel() const {
    return mLogLevel;
}
