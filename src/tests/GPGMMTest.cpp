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

static std::unique_ptr<gpgmm::DebugPlatform> mDebugPlatform(gpgmm::CreateDebugPlatform());

GPGMMTestBase::~GPGMMTestBase() {
}

void GPGMMTestBase::SetUp() {
    if (mDebugPlatform != nullptr) {
        mDebugPlatform->ReportMemoryLeaks();
    }
}

void GPGMMTestBase::TearDown() {
}

gpgmm::DebugPlatform* GPGMMTestBase::GetDebugPlatform() {
    return mDebugPlatform.get();
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
