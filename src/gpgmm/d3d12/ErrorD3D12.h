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
#ifndef GPGMM_D3D12_ERRORD3D12_H_
#define GPGMM_D3D12_ERRORD3D12_H_

#include "gpgmm/d3d12/d3d12_platform.h"
#include "gpgmm/utils/Compiler.h"

#include <string>

namespace gpgmm::d3d12 {

#define ReturnIfFailed(expr)              \
    {                                     \
        HRESULT hr = expr;                \
        if (GPGMM_UNLIKELY(FAILED(hr))) { \
            return hr;                    \
        }                                 \
    }                                     \
    for (;;)                              \
    break

#define ReturnIfSucceeded(expr)            \
    {                                      \
        HRESULT hr = expr;                 \
        if (GPGMM_LIKELY(SUCCEEDED(hr))) { \
            return hr;                     \
        }                                  \
    }                                      \
    for (;;)                               \
    break

    std::string GetErrorMessage(HRESULT error);

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_ERRORD3D12_H_
