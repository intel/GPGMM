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

#ifndef GPGMM_COMMON_DEFAULTS_H_
#define GPGMM_COMMON_DEFAULTS_H_

#include <cstdint>

namespace gpgmm {
    static constexpr const char* kDefaultTraceFile = "gpgmm_event_trace.json";
    static constexpr float kDefaultMemoryFragmentationLimit = 0.125f;  // 1/8th or 12.5%
    static constexpr float kDefaultMemoryGrowthFactor = 1.25f;         // 25% growth
}  // namespace gpgmm

#endif  // GPGMM_COMMON_DEFAULTS_H_
