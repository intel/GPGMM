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

#include <gtest/gtest.h>

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/utils/Limits.h"

using namespace gpgmm;

TEST(SizeClassTests, SizeToUnits) {
    EXPECT_EQ(GetBytesToSizeInUnits(1), "1 B");
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_KB_TO_BYTES(1)), "1 KB");
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_MB_TO_BYTES(1)), "1 MB");
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_GB_TO_BYTES(1)), "1 GB");
    EXPECT_EQ(GetBytesToSizeInUnits(kInvalidSize), "INVALID_SIZE");

    EXPECT_EQ(GetBytesToSizeInUnits(1024), "1 KB");
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_KB_TO_BYTES(1024)), "1 MB");
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_MB_TO_BYTES(1024)), "1 GB");

    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_MB_TO_BYTES(2)), "2 MB");
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_MB_TO_BYTES(20)), "20 MB");
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_MB_TO_BYTES(200)), "200 MB");
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_MB_TO_BYTES(2000)), "1 GB");  // Must be 2048 for 2GB
    EXPECT_EQ(GetBytesToSizeInUnits(GPGMM_MB_TO_BYTES(2048)), "2 GB");
}
