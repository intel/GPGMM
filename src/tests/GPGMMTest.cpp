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

#include "src/tests/GPGMMTest.h"
#include "gpgmm/common/Platform.h"

#include <iostream>

static GPGMMTestEnvironment* gTestEnv = nullptr;

#if defined(GPGMM_PLATFORM_WIN32)
#    include <crtdbg.h>
#endif

void ReportMemoryLeaks() {
#if GPGMM_PLATFORM_WIN32
    // Send all reports to STDOUT.
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDOUT);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDOUT);
    // Perform automatic leak checking at program exit through a call to _CrtDumpMemoryLeaks
    // and generate an error report if the application failed to free all the memory it
    // allocated.
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
}

GPGMMTestBase::~GPGMMTestBase() {
}

void GPGMMTestBase::SetUp() {
    ReportMemoryLeaks();
}

void GPGMMTestBase::TearDown() {
}

// GPGMMTestEnvironment

void InitGPGMMEnd2EndTestEnvironment(int argc, char** argv) {
    gTestEnv = new GPGMMTestEnvironment();
    testing::AddGlobalTestEnvironment(gTestEnv);
}

// static
void GPGMMTestEnvironment::SetEnvironment(GPGMMTestEnvironment* env) {
    gTestEnv = env;
}

void GPGMMTestEnvironment::SetUp() {
}
