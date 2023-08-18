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

#include <string>
#include <utility>

// Generates a unique variable name to avoid variable shadowing with result variables.
#define GPGMM_CONCAT1(x, y) x##y
#define GPGMM_CONCAT2(x, y) GPGMM_CONCAT1(x, y)
#define GPGMM_LOCAL_VAR(name) GPGMM_CONCAT2(GPGMM_CONCAT2(_localVar, __LINE__), name)

#define GPGMM_TRY_ASSIGN(expr, value)                               \
    {                                                               \
        auto GPGMM_LOCAL_VAR(Result) = expr;                        \
        if (GPGMM_UNLIKELY(!GPGMM_LOCAL_VAR(Result).IsSuccess())) { \
            return GPGMM_LOCAL_VAR(Result);                         \
        }                                                           \
        value = GPGMM_LOCAL_VAR(Result).AcquireResult();            \
    }                                                               \
    for (;;)                                                        \
    break

#define GPGMM_RETURN_IF_ERROR(expr)                                 \
    {                                                               \
        auto GPGMM_LOCAL_VAR(Result) = expr;                        \
        if (GPGMM_UNLIKELY(!GPGMM_LOCAL_VAR(Result).IsSuccess())) { \
            return GPGMM_LOCAL_VAR(Result).AcquireError();          \
        }                                                           \
    }                                                               \
    for (;;)                                                        \
    break

#define GPGMM_RETURN_ERROR_IF(obj, expr, msg, error) \
    if (GPGMM_UNLIKELY(expr)) {                      \
        gpgmm::ErrorLog(error, obj) << msg;          \
        return std::move(error);                     \
    }                                                \
    for (;;)                                         \
    break

#define GPGMM_RETURN_IF_NOT_FATAL(expr)                                                 \
    {                                                                                   \
        auto GPGMM_LOCAL_VAR(Result) = expr;                                            \
        if (GPGMM_LIKELY(GPGMM_LOCAL_VAR(Result).IsSuccess()) ||                        \
            GPGMM_UNLIKELY(IsErrorCodeFatal(GPGMM_LOCAL_VAR(Result).GetErrorCode()))) { \
            return GPGMM_LOCAL_VAR(Result).AcquireError();                              \
        }                                                                               \
    }                                                                                   \
    for (;;)                                                                            \
    break

namespace gpgmm {

    enum class ErrorCode : uint32_t {
        kNone,
        kUnknown,
        kSizeExceeded,
        kAllocationFailed,
        kPrefetchFailed,
        kBudgetInvalid,
        kInvalidArgument,
        kBadOperation,
        kUnsupported,
        kOutOfMemoryAndFatal,
        kOutOfMemory
    };

    const char* GetErrorCodeToChar(ErrorCode errorCode);

    bool IsErrorCodeFatal(ErrorCode errorCode);

    std::string GetErrorCodeToString(ErrorCode error) noexcept;

    // Wraps a backend error code with a result object.
    // Use Result::IsSuccess then Result::AcquireResult to use or else, use Result::GetErrorCode to
    // return the error for backend-specific handling.
    template <typename ErrorT, typename ValueT>
    class Result {
      public:
        // Empty result with error.
        Result() : mError(ErrorCode::kUnknown) {
            mValue = {};
        }

        // Error only result
        Result(ErrorT&& error) : mError(std::move(error)) {
            mValue = {};
        }

        // Result but with no error
        Result(ValueT&& result) : mError(ErrorCode::kNone), mValue(std::move(result)) {
        }

        // Result with error.
        Result(ErrorT&& error, ValueT&& result)
            : mError(std::move(error)), mValue(std::move(result)) {
        }

        Result(Result<ValueT, ErrorT>&& other)
            : mError(std::move(other.mError), mValue(std::move(other.mValue))) {
        }

        Result<ValueT, ErrorT>& operator=(Result<ValueT, ErrorT>&& other) {
            mValue = std::move(other.mValue);
            mError = std::move(other.mError);
            return *this;
        }

        ErrorCode GetErrorCode() const {
            return mError;
        }

        ValueT&& AcquireResult() {
            return std::move(mValue);
        }

        ErrorT&& AcquireError() {
            return std::move(mError);
        }

        bool IsSuccess() const {
            return mError == ErrorCode::kNone;
        }

        // Implicit conversion to MaybeError.
        // Used by GPGMM_TRY_ASSIGN on error result.
        operator Result<ErrorT, void>() {
            return AcquireError();
        }

      private:
        ErrorT mError;
        ValueT mValue;
    };

    // Specialization of Result<ErrorT, ValueT> where the ValueT is void.
    // Used when a void function must return a Result with only error code.
    template <typename ErrorT>
    class Result<ErrorT, void> {
      public:
        // Result with no error.
        Result() : mError(ErrorCode::kNone) {
        }

        // Result with error.
        Result(ErrorT&& error) : mError(std::move(error)) {
        }

        Result(Result<ErrorT, void>&& other) : mError(std::move(other.mError)) {
        }

        Result<ErrorT, void>& operator=(Result<ErrorT, void>&& other) {
            mError = std::move(other.mError);
            return *this;
        }

        ErrorCode GetErrorCode() const {
            return mError;
        }

        bool IsSuccess() const {
            return mError == ErrorCode::kNone;
        }

        ErrorT&& AcquireError() {
            return std::move(mError);
        }

      private:
        ErrorT mError;
    };

    // Result with only an error code.
    using MaybeError = Result<ErrorCode, void>;

    // Alias of Result + error code to avoid having to always specify error type.
    template <typename ValueT>
    using ResultOrError = Result<ErrorCode, ValueT>;

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_ERROR_H_
