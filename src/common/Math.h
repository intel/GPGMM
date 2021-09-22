// Copyright 2017 The Dawn Authors
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

#ifndef GPGMM_COMMON_MATH_H_
#define GPGMM_COMMON_MATH_H_

#include "Assert.h"

#include <cstddef>
#include <cstdint>

#include <limits>

namespace gpgmm {

    // The following are not valid for 0
    uint32_t ScanForward(uint32_t bits);
    uint32_t Log2(uint32_t value);
    uint32_t Log2(uint64_t value);
    bool IsPowerOfTwo(uint64_t n);

    uint64_t NextPowerOfTwo(uint64_t n);
    bool IsAligned(uint32_t value, size_t alignment);

    template <typename T>
    T Align(T value, size_t alignment) {
        ASSERT(value <= std::numeric_limits<T>::max() - (alignment - 1));
        ASSERT(IsPowerOfTwo(alignment));
        ASSERT(alignment != 0);
        T alignmentT = static_cast<T>(alignment);
        return (value + (alignmentT - 1)) & ~(alignmentT - 1);
    }

}  // namespace gpgmm

#endif  // GPGMM_COMMON_MATH_H_
