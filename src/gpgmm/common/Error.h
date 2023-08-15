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

#ifndef SRC_GPGMM_COMMON_ERROR_H_
#define SRC_GPGMM_COMMON_ERROR_H_

#include "gpgmm/utils/Assert.h"

#include <utility>

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

#define GPGMM_RETURN_IF_ERROR(expr)                \
    {                                              \
        auto result = expr;                        \
        if (GPGMM_UNLIKELY(!result.IsSuccess())) { \
            return result.AcquireError();          \
        }                                          \
    }                                              \
    for (;;)                                       \
    break

#define GPGMM_RETURN_ERROR_IF(obj, expr, msg, error) \
    if (GPGMM_UNLIKELY(expr)) {                      \
        gpgmm::ErrorLog(error, obj) << msg;          \
        return std::move(error);                     \
    }                                                \
    for (;;)                                         \
    break

namespace gpgmm {

    enum class ErrorCode : uint32_t {
        kNone,
        kUnknown,
        kSizeExceeded,
        kAllocatorFailed,
        kPrefetchFailed,
        kBudgetInvalid,
        kInvalidArgument,
        kBadOperation,
        kValidationError,
    };

    const char* GetErrorCodeToChar(ErrorCode errorCode);

    // Wraps a backend error code with a result object.
    // Use Result::IsSuccess then Result::AcquireResult to use or else, use Result::GetErrorCode to
    // return the error for backend-specific handling.
    template <typename ErrorT, typename ResultT>
    class Result {
      public:
        // Empty result with error.
        Result() : mErrorCode(ErrorCode::kUnknown) {
            mResult = {};
        }

        // Error only result
        Result(ErrorT&& error) : mErrorCode(std::move(error)) {
            mResult = {};
        }

        // Result but with no error
        Result(ResultT&& result) : mErrorCode(ErrorCode::kNone), mResult(std::move(result)) {
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

        ErrorCode GetErrorCode() const {
            return mErrorCode;
        }

        ResultT&& AcquireResult() {
            return std::move(mResult);
        }

        ErrorT&& AcquireError() {
            return std::move(mErrorCode);
        }

        bool IsSuccess() const {
            return mErrorCode == ErrorCode::kNone;
        }

      private:
        ErrorT mErrorCode;
        ResultT mResult;
    };

    // Specialization of Result<ErrorT, ResultT> where the ResultT is void.
    // Used when a void function must return a Result with only error code.
    template <typename ErrorT>
    class Result<ErrorT, void> {
      public:
        // Result with no error.
        Result() : mErrorCode(ErrorCode::kNone) {
        }

        // Result with error.
        Result(ErrorT&& error) : mErrorCode(std::move(error)) {
        }

        Result(Result<ErrorT, void>&& other) : mErrorCode(std::move(other.mErrorCode)) {
        }

        Result<ErrorT, void>& operator=(Result<ErrorT, void>&& other) {
            mErrorCode = std::move(other.mErrorCode);
            return *this;
        }

        bool IsSuccess() const {
            return mErrorCode == ErrorCode::kNone;
        }

        ErrorT&& AcquireError() {
            return std::move(mErrorCode);
        }

      private:
        ErrorT mErrorCode;
    };

    // Result with only an error code.
    using MaybeError = Result<ErrorCode, void>;

    // Alias of Result + error code to avoid having to always specify error type.
    template <typename ResultT>
    using ResultOrError = Result<ErrorCode, ResultT>;

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_ERROR_H_
