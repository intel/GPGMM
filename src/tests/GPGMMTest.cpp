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

#include <iostream>

static GPGMMTestEnvironment* gTestEnv = nullptr;

GPGMMTestBase::~GPGMMTestBase() {
}

void GPGMMTestBase::SetUp() {
}

void GPGMMTestBase::TearDown() {
}

bool GPGMMTestBase::IsDeviceLeakChecksEnabled() const {
    return gTestEnv->IsDeviceLeakChecksEnabled();
}

// GPGMMTestEnvironment

void InitGPGMMEnd2EndTestEnvironment(int argc, char** argv) {
    gTestEnv = new GPGMMTestEnvironment(argc, argv);
    testing::AddGlobalTestEnvironment(gTestEnv);
}

GPGMMTestEnvironment::GPGMMTestEnvironment(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp("--check-device-leaks", argv[i]) == 0) {
            mEnableCheckDeviceLeaks = true;
            continue;
        }
    }

    PrintTestEnviromentSettings();
}

// static
void GPGMMTestEnvironment::SetEnvironment(GPGMMTestEnvironment* env) {
    gTestEnv = env;
}

void GPGMMTestEnvironment::SetUp() {
}

bool GPGMMTestEnvironment::IsDeviceLeakChecksEnabled() const {
    return mEnableCheckDeviceLeaks;
}

void GPGMMTestEnvironment::PrintTestEnviromentSettings() const {
    std::cout << "Test enviroment settings\n"
                 "------------------------\n"
              << "Enable check device leaks: " << (mEnableCheckDeviceLeaks ? "true" : "false")
              << "\n"
              << std::endl;
}
