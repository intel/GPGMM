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

#include <gtest/gtest.h>

// Make sure DEFINE_ENUM_FLAG_OPERATORS is being tested is from GPGMM.
#undef DEFINE_ENUM_FLAG_OPERATORS

#include "gpgmm/utils/EnumFlags.h"

#include <sstream>

namespace gpgmm {

    enum CountFlags {
        kZero,
        kOne = 1,
        kTwo = 2,
        kThree = 3,
    };

    DEFINE_ENUM_FLAG_OPERATORS(CountFlags)

    TEST(EnumFlagsTests, Basic) {
        CountFlags a = kZero;

        a |= kOne;
        EXPECT_TRUE(a == kOne);
        EXPECT_EQ(a, 1);

        a |= kTwo;
        EXPECT_TRUE(a == kThree);
        EXPECT_EQ(a, 3);

        a &= kTwo;
        EXPECT_TRUE(a == kTwo);
        EXPECT_EQ(a, 2);

        a ^= kTwo;
        EXPECT_TRUE(a == kZero);
        EXPECT_EQ(a, 0);
    }

    struct Desc {
        enum OptionFlags {
            kNone,
            kFirst = 1,
            kSecond = 2,
            kThird = 3,
            kFourth = 4,
        };
    };

    DEFINE_ENUM_FLAG_OPERATORS(Desc::OptionFlags)

    TEST(EnumFlagsTests, Struct) {
        Desc::OptionFlags a = Desc::OptionFlags::kNone;
        a |= Desc::kFirst;
        EXPECT_TRUE(a == Desc::kFirst);

        {
            std::stringstream ss;
            ss << a;
            EXPECT_EQ(ss.str(), "1");
        }

        a |= Desc::kSecond;
        EXPECT_TRUE(a == Desc::kThird);

        {
            std::stringstream ss;
            ss << a;
            EXPECT_EQ(ss.str(), "3");
        }
    }

    TEST(EnumFlagsTests, HasAllFlags) {
        Desc::OptionFlags firstAndSecond = Desc::kFirst | Desc::kSecond;
        EXPECT_TRUE(HasAllFlags(firstAndSecond, Desc::kSecond));
        EXPECT_TRUE(HasAllFlags(firstAndSecond, Desc::kFirst));
        EXPECT_FALSE(HasAllFlags(firstAndSecond, Desc::kFourth));
    }

}  // namespace gpgmm
