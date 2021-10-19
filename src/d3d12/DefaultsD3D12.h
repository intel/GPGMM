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

namespace gpgmm { namespace d3d12 {

    static constexpr uint64_t kDefaultMaxResourceHeapSize =
        32ll * 1024ll * 1024ll * 1024ll;                                                   // 32GB
    static constexpr uint64_t kDefaultPreferredResourceHeapSize = 4ll * 1024ll * 1024ll;   // 4MB
    static constexpr uint32_t kDefaultResidentResourceEvictSize = 50ll * 1024ll * 1024ll;  // 50MB
    static constexpr float kDefaultMaxVideoMemoryBudget = 0.95f;                           // 95%

}}  // namespace gpgmm::d3d12

#endif  // COMMON_LIMITS_H_
