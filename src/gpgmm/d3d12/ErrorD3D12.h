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

#ifndef SRC_GPGMM_D3D12_ERRORD3D12_H_
#define SRC_GPGMM_D3D12_ERRORD3D12_H_

#include "gpgmm/common/Error.h"
#include "gpgmm/d3d12/D3D12Platform.h"
#include "gpgmm/utils/Compiler.h"
#include "gpgmm/utils/Log.h"

#include <string>

#define GPGMM_RETURN_IF_NULL(ptr) \
    GPGMM_RETURN_IF_FAILED((ptr == nullptr ? E_POINTER : S_OK), nullptr)

// For D3D12 calls that could remove device, the (optional) device ptr should be supplied as the
// last argument so the reason can be appended the result message.
#define GPGMM_RETURN_IF_FAILED(expr, ...)                                                         \
    {                                                                                             \
        auto GPGMM_LOCAL_VAR(HRESULT) = expr;                                                     \
        if (GPGMM_UNLIKELY(FAILED(GPGMM_LOCAL_VAR(HRESULT)))) {                                   \
            gpgmm::ErrorLog(GetErrorCode(GPGMM_LOCAL_VAR(HRESULT)))                               \
                << #expr << ": " << GetErrorResultMessage(GPGMM_LOCAL_VAR(HRESULT), __VA_ARGS__); \
            return GPGMM_LOCAL_VAR(HRESULT);                                                      \
        }                                                                                         \
    }                                                                                             \
    for (;;)                                                                                      \
    break

#define GPGMM_RETURN_IF_SUCCEEDED(expr)                          \
    {                                                            \
        auto GPGMM_LOCAL_VAR(HRESULT) = expr;                    \
        if (GPGMM_LIKELY(SUCCEEDED(GPGMM_LOCAL_VAR(HRESULT)))) { \
            return GPGMM_LOCAL_VAR(HRESULT);                     \
        }                                                        \
    }                                                            \
    for (;;)                                                     \
    break

// Same as FAILED but also returns true if S_FALSE.
// S_FALSE is used to denote a HRESULT where the operation didn't do anything.
// For example, passing NULL to create an object without returning it.
#define GPGMM_UNSUCCESSFUL(hr) (FAILED(hr) || (hr == S_FALSE))

namespace gpgmm::d3d12 {

    HRESULT GetErrorResult(ErrorCode error);
    ErrorCode GetErrorCode(HRESULT error);

    // Returns non device removal HRESULT error as a printable message.
    std::string GetErrorResultMessage(HRESULT error);

    // Returns device removal HRESULT error as a printable message.
    std::string GetErrorResultMessage(HRESULT error, ID3D12Device* device);

    std::string GetErrorResultToString(HRESULT error) noexcept;

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_ERRORD3D12_H_
