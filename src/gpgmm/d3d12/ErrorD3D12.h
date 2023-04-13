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
#ifndef GPGMM_D3D12_ERRORD3D12_H_
#define GPGMM_D3D12_ERRORD3D12_H_

#include "gpgmm/common/Error.h"
#include "gpgmm/d3d12/D3D12Platform.h"
#include "gpgmm/utils/Compiler.h"
#include "gpgmm/utils/Log.h"

#include <string>

#define GPGMM_RETURN_IF_NULLPTR(expr)                                         \
    {                                                                         \
        if (GPGMM_UNLIKELY(expr == nullptr)) {                                \
            gpgmm::ErrorLog() << #expr << ": " << GetErrorMessage(E_POINTER); \
            return E_POINTER;                                                 \
        }                                                                     \
    }                                                                         \
    for (;;)                                                                  \
    break

#define GPGMM_RETURN_IF_FAILED(expr, device)                                         \
    {                                                                                \
        HRESULT hr = expr;                                                           \
        if (GPGMM_UNLIKELY(FAILED(hr))) {                                            \
            gpgmm::ErrorLog() << #expr << ": " << GetDeviceErrorMessage(device, hr); \
            return hr;                                                               \
        }                                                                            \
    }                                                                                \
    for (;;)                                                                         \
    break

#define GPGMM_RETURN_IF_SUCCEEDED(expr)    \
    {                                      \
        HRESULT hr = expr;                 \
        if (GPGMM_LIKELY(SUCCEEDED(hr))) { \
            return hr;                     \
        }                                  \
    }                                      \
    for (;;)                               \
    break

// Same as GPGMM_RETURN_IF_SUCCEEDED but also returns if error is lethal.
// Non-internal errors are always fatal and should not run re-attempt logic.
#define GPGMM_RETURN_IF_SUCCEEDED_OR_FATAL(expr)                                  \
    {                                                                             \
        HRESULT hr = expr;                                                        \
        if (GPGMM_LIKELY(SUCCEEDED(hr)) ||                                        \
            GPGMM_UNLIKELY(hr != static_cast<HRESULT>(kInternalFailureResult))) { \
            return hr;                                                            \
        }                                                                         \
    }                                                                             \
    for (;;)                                                                      \
    break

#define GPGMM_ASSERT_IF_FAILED(expr) ASSERT(SUCCEEDED(expr));
#define GPGMM_ASSERT_IF_SUCCEEDED(expr) ASSERT(FAILED(expr));

namespace gpgmm::d3d12 {

    std::string GetDeviceErrorMessage(ID3D12Device* device, HRESULT error);
    std::string GetErrorMessage(HRESULT error) noexcept;

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_ERRORD3D12_H_
