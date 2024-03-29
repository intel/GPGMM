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
#ifndef SRC_GPGMM_VK_ERRORVK_H_
#define SRC_GPGMM_VK_ERRORVK_H_

#include "gpgmm/common/Error.h"
#include "gpgmm/vk/VKPlatform.h"

namespace gpgmm::vk {

#define GPGMM_RETURN_IF_FAILED(expr) \
    {                                \
        VkResult result = expr;      \
        if (result != VK_SUCCESS) {  \
            return result;           \
        }                            \
    }                                \
    for (;;)                         \
    break

}  // namespace gpgmm::vk

#endif  // SRC_GPGMM_VK_ERRORVK_H_
