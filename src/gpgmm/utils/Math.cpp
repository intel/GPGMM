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

#include "Math.h"

#include "Assert.h"
#include "Platform.h"

#include <algorithm>
#include <cmath>
#include <limits>

#if defined(GPGMM_COMPILER_MSVC)
#    include <intrin.h>
#endif

namespace gpgmm {

    uint32_t ScanForward(uint32_t bits) {
        ASSERT(bits != 0);
#if defined(GPGMM_COMPILER_MSVC)
        unsigned long firstBitIndex = 0ul;
        unsigned char ret = _BitScanForward(&firstBitIndex, bits);
        ASSERT(ret != 0);
        return firstBitIndex;
#else
        return static_cast<uint32_t>(__builtin_ctz(bits));
#endif
    }

    uint32_t Log2(uint32_t number) {
        ASSERT(number != 0);
#if defined(GPGMM_COMPILER_MSVC)
        unsigned long firstBitIndex = 0ul;
        unsigned char ret = _BitScanReverse(&firstBitIndex, number);
        ASSERT(ret != 0);
        return firstBitIndex;
#else
        return 31 - static_cast<uint32_t>(__builtin_clz(number));
#endif
    }

    uint32_t Log2(uint64_t number) {
        ASSERT(number != 0);
#if defined(GPGMM_COMPILER_MSVC)
#    if defined(GPGMM_PLATFORM_64_BIT)
        unsigned long firstBitIndex = 0ul;
        unsigned char ret = _BitScanReverse64(&firstBitIndex, number);
        ASSERT(ret != 0);
        return firstBitIndex;
#    else   // defined(GPGMM_PLATFORM_64_BIT)
        unsigned long firstBitIndex = 0ul;
        if (_BitScanReverse(&firstBitIndex, number >> 32)) {
            return firstBitIndex + 32;
        }
        unsigned char ret = _BitScanReverse(&firstBitIndex, number & 0xFFFFFFFF);
        ASSERT(ret != 0);
        return firstBitIndex;
#    endif  // defined(GPGMM_PLATFORM_64_BIT)
#else       // defined(GPGMM_COMPILER_MSVC)
        return 63 - static_cast<uint32_t>(__builtin_clzll(number));
#endif      // defined(GPGMM_COMPILER_MSVC)
    }

    uint64_t NextPowerOfTwo(uint64_t number) {
        if (number <= 1) {
            return 1;
        }

        return 1ull << (Log2(number - 1) + 1);
    }

    uint64_t PrevPowerOfTwo(uint64_t number) {
        ASSERT(number != 0);
        return 1ull << Log2(number);
    }

    bool IsPowerOfTwo(uint64_t number) {
        return (number == 0) ? false : (number & (number - 1)) == 0;
    }

    bool IsAligned(uint64_t number, size_t multiple) {
        ASSERT(multiple != 0);
        if (IsPowerOfTwo(multiple)) {
            return (number & (multiple - 1)) == 0;
        }
        return number % multiple == 0;
    }

    uint64_t RoundUp(uint64_t number, uint64_t multiple) {
        ASSERT(multiple > 0);
        ASSERT(number > 0);
        ASSERT(multiple <= std::numeric_limits<uint64_t>::max() - number);
        return ((number + multiple - 1) / multiple) * multiple;
    }

}  // namespace gpgmm
