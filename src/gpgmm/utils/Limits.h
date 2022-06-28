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

#ifndef GPGMM_UTILS_LIMITS_H_
#define GPGMM_UTILS_LIMITS_H_

#include <climits>  // CHAR_BIT
#include <cstdint>
#include <limits>

namespace gpgmm {

    static constexpr uint64_t kInvalidOffset = std::numeric_limits<uint64_t>::max();
    static constexpr uint64_t kInvalidSize = std::numeric_limits<uint64_t>::max();
    static constexpr uint64_t kInvalidIndex = std::numeric_limits<uint64_t>::max();

    template <typename T>
    constexpr size_t GetNumOfBits() {
        static_assert(CHAR_BIT == 8, "Size of a char is not 8 bits.");
        return sizeof(T) * CHAR_BIT;
    }

}  // namespace gpgmm

#endif  // GPGMM_UTILS_LIMITS_H_
