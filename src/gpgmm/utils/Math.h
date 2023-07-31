// Copyright 2017 The Dawn Authors
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

#ifndef SRC_GPGMM_UTILS_MATH_H_
#define SRC_GPGMM_UTILS_MATH_H_

#include "Assert.h"

#include <cstddef>
#include <cstdint>

#include <limits>

namespace gpgmm {

    // The following are not valid for 0
    uint32_t ScanForward(uint32_t bits);
    uint32_t Log2(uint32_t number);
    uint32_t Log2(uint64_t number);
    uint64_t LowerPowerOfTwo(uint64_t number);

    bool IsPowerOfTwo(uint64_t number);
    uint64_t UpperPowerOfTwo(uint64_t number);
    bool IsAligned(uint64_t number, size_t multiple);

    // Aligns number to the nearest power-of-two multiple.
    // Compatible with 32-bit or 64-bit numbers.
    template <typename T1, typename T2>
    auto AlignTo(T1 number, T2 multiple) {
        ASSERT(number <= std::numeric_limits<T1>::max() - (multiple - 1));
        ASSERT(IsPowerOfTwo(multiple));
        ASSERT(multiple != 0);
        // Use of bitwise not (~) must be avoided since a 64-bit multiple would be always ~'d to a
        // 32-bit range.
        return (number + (multiple - 1)) - ((number + (multiple - 1)) & (multiple - 1));
    }

    uint64_t RoundUp(uint64_t number, uint64_t multiple);

    // Evaluates a/b, avoiding division by zero.
    template <typename T>
    double SafeDivide(T dividend, T divisor) {
        if (divisor == 0) {
            return 0.0;
        } else {
            return dividend / static_cast<double>(divisor);
        }
    }

}  // namespace gpgmm

#endif  // SRC_GPGMM_UTILS_MATH_H_
