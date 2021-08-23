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

#ifndef COMMON_MATH_H_
#define COMMON_MATH_H_

#include "src/common/Assert.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <limits>

// The following are not valid for 0
uint32_t ScanForward(uint32_t bits);
uint32_t Log2(uint32_t value);
uint32_t Log2(uint64_t value);
bool IsPowerOfTwo(uint64_t n);
uint64_t RoundUp(uint64_t n, uint64_t m);

constexpr uint32_t ConstexprLog2(uint64_t v) {
    return v <= 1 ? 0 : 1 + ConstexprLog2(v / 2);
}

constexpr uint32_t ConstexprLog2Ceil(uint64_t v) {
    return v <= 1 ? 0 : ConstexprLog2(v - 1) + 1;
}

inline uint32_t Log2Ceil(uint32_t v) {
    return v <= 1 ? 0 : Log2(v - 1) + 1;
}

inline uint32_t Log2Ceil(uint64_t v) {
    return v <= 1 ? 0 : Log2(v - 1) + 1;
}

uint64_t NextPowerOfTwo(uint64_t n);
bool IsPtrAligned(const void* ptr, size_t alignment);
void* AlignVoidPtr(void* ptr, size_t alignment);
bool IsAligned(uint32_t value, size_t alignment);

template <typename T>
T Align(T value, size_t alignment) {
    ASSERT(value <= std::numeric_limits<T>::max() - (alignment - 1));
    ASSERT(IsPowerOfTwo(alignment));
    ASSERT(alignment != 0);
    T alignmentT = static_cast<T>(alignment);
    return (value + (alignmentT - 1)) & ~(alignmentT - 1);
}

template <typename T>
DAWN_FORCE_INLINE T* AlignPtr(T* ptr, size_t alignment) {
    ASSERT(IsPowerOfTwo(alignment));
    ASSERT(alignment != 0);
    return reinterpret_cast<T*>((reinterpret_cast<size_t>(ptr) + (alignment - 1)) &
                                ~(alignment - 1));
}

template <typename T>
DAWN_FORCE_INLINE const T* AlignPtr(const T* ptr, size_t alignment) {
    ASSERT(IsPowerOfTwo(alignment));
    ASSERT(alignment != 0);
    return reinterpret_cast<const T*>((reinterpret_cast<size_t>(ptr) + (alignment - 1)) &
                                      ~(alignment - 1));
}

#endif  // COMMON_MATH_H_
