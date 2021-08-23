// Copyright 2017 The Dawn Authors
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

#include "src/common/Math.h"

#include "src/common/Assert.h"
#include "src/common/Platform.h"

#include <algorithm>
#include <cmath>
#include <limits>

#if defined(DAWN_COMPILER_MSVC)
#    include <intrin.h>
#endif

uint32_t ScanForward(uint32_t bits) {
    ASSERT(bits != 0);
#if defined(DAWN_COMPILER_MSVC)
    unsigned long firstBitIndex = 0ul;
    unsigned char ret = _BitScanForward(&firstBitIndex, bits);
    ASSERT(ret != 0);
    return firstBitIndex;
#else
    return static_cast<uint32_t>(__builtin_ctz(bits));
#endif
}

uint32_t Log2(uint32_t value) {
    ASSERT(value != 0);
#if defined(DAWN_COMPILER_MSVC)
    unsigned long firstBitIndex = 0ul;
    unsigned char ret = _BitScanReverse(&firstBitIndex, value);
    ASSERT(ret != 0);
    return firstBitIndex;
#else
    return 31 - static_cast<uint32_t>(__builtin_clz(value));
#endif
}

uint32_t Log2(uint64_t value) {
    ASSERT(value != 0);
#if defined(DAWN_COMPILER_MSVC)
#    if defined(DAWN_PLATFORM_64_BIT)
    unsigned long firstBitIndex = 0ul;
    unsigned char ret = _BitScanReverse64(&firstBitIndex, value);
    ASSERT(ret != 0);
    return firstBitIndex;
#    else   // defined(DAWN_PLATFORM_64_BIT)
    unsigned long firstBitIndex = 0ul;
    if (_BitScanReverse(&firstBitIndex, value >> 32)) {
        return firstBitIndex + 32;
    }
    unsigned char ret = _BitScanReverse(&firstBitIndex, value & 0xFFFFFFFF);
    ASSERT(ret != 0);
    return firstBitIndex;
#    endif  // defined(DAWN_PLATFORM_64_BIT)
#else       // defined(DAWN_COMPILER_MSVC)
    return 63 - static_cast<uint32_t>(__builtin_clzll(value));
#endif      // defined(DAWN_COMPILER_MSVC)
}

uint64_t NextPowerOfTwo(uint64_t n) {
    if (n <= 1) {
        return 1;
    }

    return 1ull << (Log2(n - 1) + 1);
}

bool IsPowerOfTwo(uint64_t n) {
    ASSERT(n != 0);
    return (n & (n - 1)) == 0;
}

bool IsPtrAligned(const void* ptr, size_t alignment) {
    ASSERT(IsPowerOfTwo(alignment));
    ASSERT(alignment != 0);
    return (reinterpret_cast<size_t>(ptr) & (alignment - 1)) == 0;
}

bool IsAligned(uint32_t value, size_t alignment) {
    ASSERT(alignment <= UINT32_MAX);
    ASSERT(IsPowerOfTwo(alignment));
    ASSERT(alignment != 0);
    uint32_t alignment32 = static_cast<uint32_t>(alignment);
    return (value & (alignment32 - 1)) == 0;
}

uint64_t RoundUp(uint64_t n, uint64_t m) {
    ASSERT(m > 0);
    ASSERT(n > 0);
    ASSERT(m <= std::numeric_limits<uint64_t>::max() - n);
    return ((n + m - 1) / m) * m;
}
