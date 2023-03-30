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

#ifndef GPGMM_COMMON_ERROR_H_
#define GPGMM_COMMON_ERROR_H_

#include "gpgmm/utils/Assert.h"

#include <utility>

namespace gpgmm {

    enum class ErrorCodeType : uint32_t;

    constexpr ErrorCodeType kInternalFailureResult = static_cast<ErrorCodeType>(-1);
    constexpr ErrorCodeType kInternalSuccessResult = static_cast<ErrorCodeType>(0u);

    // Wraps a backend error code with a result object.
    // Use Result::IsSuccess then Result::AcquireResult to use or else, use Result::GetErrorCode to
    // return the error for backend-specific handling.
    template <typename ErrorT, typename ResultT>
    class Result {
      public:
        // Empty result
        Result() : mErrorCode(kInternalFailureResult) {
            mResult = {};
        }

        // Error only result
        Result(ErrorT&& error) : mErrorCode(std::move(error)) {
            mResult = {};
        }

        // Result but with no error
        Result(ResultT&& result) : mErrorCode(kInternalSuccessResult), mResult(std::move(result)) {
        }

        // Result with error.
        Result(ErrorT&& error, ResultT&& result)
            : mErrorCode(std::move(error)), mResult(std::move(result)) {
        }

        Result(Result<ResultT, ErrorT>&& other)
            : mErrorCode(std::move(other.mErrorCode), mResult(std::move(other.mResult))) {
        }

        Result<ResultT, ErrorT>& operator=(Result<ResultT, ErrorT>&& other) {
            mResult = std::move(other.mResult);
            mErrorCode = std::move(other.mErrorCode);
            return *this;
        }

        ErrorCodeType GetErrorCode() const {
            return mErrorCode;
        }

        ResultT&& AcquireResult() {
            return std::move(mResult);
        }

        bool IsSuccess() const {
            return mErrorCode == kInternalSuccessResult;
        }

      private:
        ErrorT mErrorCode;
        ResultT mResult;
    };

    // Alias of Result + error code to avoid having to always specify error type.
    template <typename ResultT>
    using ResultOrError = Result<ErrorCodeType, ResultT>;

#define GPGMM_INVALID_ALLOCATION \
    MemoryAllocation {                 \
    }

#define GPGMM_TRY_ASSIGN(expr, value)              \
    {                                              \
        auto result = expr;                        \
        if (GPGMM_UNLIKELY(!result.IsSuccess())) { \
            return result;                         \
        }                                          \
        value = result.AcquireResult();            \
    }                                              \
    for (;;)                                       \
    break

#define GPGMM_INVALID_IF(expr)  \
    if (GPGMM_UNLIKELY(expr)) { \
        return {};              \
    }                           \
    for (;;)                    \
    break

}  // namespace gpgmm

#endif  // GPGMM_COMMON_ERROR_H_
