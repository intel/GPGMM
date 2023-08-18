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

#define GPGMM_RETURN_IF_NULLPTR(ptr) \
    GPGMM_RETURN_IF_FAILED((ptr == nullptr ? E_POINTER : S_OK), nullptr)

#define GPGMM_RETURN_IF_FAILED(expr, device)                                          \
    {                                                                                 \
        auto GPGMM_LOCAL_VAR(HRESULT) = expr;                                         \
        if (GPGMM_UNLIKELY(FAILED(GPGMM_LOCAL_VAR(HRESULT)))) {                       \
            gpgmm::ErrorLog(GetErrorCode(GPGMM_LOCAL_VAR(HRESULT)))                   \
                << #expr << ": "                                                      \
                << GetErrorResultWithRemovalReason(GPGMM_LOCAL_VAR(HRESULT), device); \
            return GPGMM_LOCAL_VAR(HRESULT);                                          \
        }                                                                             \
    }                                                                                 \
    for (;;)                                                                          \
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

#define GPGMM_ASSERT_FAILED(hr) ASSERT(SUCCEEDED(hr));
#define GPGMM_ASSERT_SUCCEEDED(hr) ASSERT(FAILED(hr));

namespace gpgmm::d3d12 {

    HRESULT GetErrorResult(ErrorCode error);
    ErrorCode GetErrorCode(HRESULT error);
    bool IsErrorResultFatal(HRESULT error);

    // Returns HRESULT error as a printable message.
    // If the device is also specified and removed, a detailed message is supplied.
    std::string GetErrorResultWithRemovalReason(HRESULT error, ID3D12Device* device);
    std::string GetErrorResultToString(HRESULT error) noexcept;

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_ERRORD3D12_H_
