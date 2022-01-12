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

#include "gpgmm/common/Flags.h"

namespace gpgmm {

    enum Count {
        kZero,
        kOne = 1,
        kTwo = 2,
        kThree = 3,
    };

    using CountFlags = Flags<Count>;
    DEFINE_OPERATORS_FOR_FLAGS(CountFlags)

    TEST(FlagsTests, Basic) {
        CountFlags a;
        a |= kZero;
        EXPECT_TRUE(a == kZero);

        a |= kOne;
        EXPECT_TRUE(a == kOne);

        a |= kTwo;
        EXPECT_TRUE(a == kThree);

        a &= kTwo;
        EXPECT_TRUE(a == kTwo);

        a ^= kTwo;
        EXPECT_TRUE(a == kZero);
    }

    struct Desc {
        enum Count {
            kZero,
            kOne = 1,
            kTwo = 2,
            kThree = 3,
        };

        using CountFlags = Flags<Count>;
    };

    DEFINE_OPERATORS_FOR_FLAGS(Desc::CountFlags)

    TEST(FlagsTests, struct) {
        Desc::CountFlags a;
        a |= Desc::kOne;
        EXPECT_TRUE(a == Desc::kOne);

        a |= Desc::kTwo;
        EXPECT_TRUE(a == Desc::kThree);
    }

}  // namespace gpgmm
