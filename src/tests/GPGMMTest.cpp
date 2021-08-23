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

static GPGMMTestEnvironment* gTestEnv = nullptr;

void InitGPGMMEnd2EndTestEnvironment() {
    gTestEnv = new GPGMMTestEnvironment();
    testing::AddGlobalTestEnvironment(gTestEnv);
}

void GPGMMTest::SetUp() {
}

GPGMMTest::~GPGMMTest() {
}

void GPGMMTest::TearDown() {
}

void GPGMMTestEnvironment::SetUp() {
}