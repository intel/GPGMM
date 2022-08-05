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

#ifndef GPGMM_COMMON_ERROR_H_
#define GPGMM_COMMON_ERROR_H_

#include "gpgmm/utils/Assert.h"

namespace gpgmm {

#define GPGMM_ERROR_INVALID_ALLOCATION \
    MemoryAllocation {                 \
    }

#define GPGMM_TRY_ASSIGN(expr, value)            \
    {                                            \
        auto result = expr;                      \
        if (GPGMM_UNLIKELY(result == nullptr)) { \
            return {};                           \
        }                                        \
        value = std::move(result);               \
    }                                            \
    for (;;)                                     \
    break

#define GPGMM_INVALID_IF(expr)  \
    if (GPGMM_UNLIKELY(expr)) { \
        return {};              \
    }                           \
    for (;;)                    \
    break

}  // namespace gpgmm

#endif  // GPGMM_COMMON_ERROR_H_
