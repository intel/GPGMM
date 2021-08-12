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

#ifndef COMMON_LIMITS_H_
#define COMMON_LIMITS_H_

#include <cstdint>

namespace gpgmm {

    static constexpr uint64_t kMaxHeapSize = 32ll * 1024ll * 1024ll * 1024ll;  // 32GB
    static constexpr uint64_t kDefaultHeapSize = 4ll * 1024ll * 1024ll;        // 4MB

}  // namespace gpgmm

#endif  // COMMON_LIMITS_H_
