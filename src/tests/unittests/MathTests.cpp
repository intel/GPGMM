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

#include "gpgmm/utils/Math.h"

using namespace gpgmm;

TEST(MathTests, Basic) {
    // a/b = c
    EXPECT_EQ(SafeDivide(100, 0), 0.0);
    EXPECT_EQ(SafeDivide(100, 10), 10);
    EXPECT_EQ(SafeDivide(1.25, 2.0), 0.625);
}

TEST(MathTests, IsPowerOfTwo) {
    // Check if number is POT.
    EXPECT_FALSE(IsPowerOfTwo(0u));  // 2^0 = 0
    EXPECT_TRUE(IsPowerOfTwo(1u));   // 2^0 = 1
    EXPECT_TRUE(IsPowerOfTwo(2u));   // 2^1 = 2
    EXPECT_TRUE(IsPowerOfTwo(4u));   // 2^2 = 4

    // Check if number is NPOT.
    EXPECT_FALSE(IsPowerOfTwo(3u));
}

TEST(MathTests, PrevPowerOfTwo) {
    // Check number from POT.
    EXPECT_EQ(PrevPowerOfTwo(1u), 1u);
    EXPECT_EQ(PrevPowerOfTwo(2u), 2u);

    // Check number from NPOT.
    EXPECT_EQ(PrevPowerOfTwo(3u), 2u);
    EXPECT_EQ(PrevPowerOfTwo(9u), 8u);
    EXPECT_EQ(PrevPowerOfTwo(15u), 8u);

    EXPECT_EQ(PrevPowerOfTwo((2ull << 31) + 1), 2ull << 31);
}

TEST(MathTests, IsAligned) {
    // Check if a POT number is NOT aligned with a NPOT multiple.
    EXPECT_FALSE(IsAligned(2u, 3u));

    // Check if a NPOT number is aligned with a NPOT multiple.
    EXPECT_TRUE(IsAligned(6u, 3u));

    // Check if a POT number is aligned with a POT multiple.
    EXPECT_TRUE(IsAligned(8u, 4u));

    // Check if a NPOT number is NOT aligned with a POT multiple.
    EXPECT_FALSE(IsAligned(7u, 4u));
}

TEST(MathTests, AlignTo) {
    // Align NPOT number with POT multiple.
    EXPECT_EQ(AlignTo(10u, 16), 16u);
    EXPECT_EQ(AlignTo(16u, 16u), 16u);

    // Align UINT32_MAX to POT multiple.
    ASSERT_EQ(AlignTo(static_cast<uint64_t>(0xFFFFFFFF), 4ull), 0x100000000u);

    // Align UINT64_MAX to POT multiple.
    ASSERT_EQ(AlignTo(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), 1ull), 0xFFFFFFFFFFFFFFFFull);
}
