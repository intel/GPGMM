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

#include "Error.h"

#include "gpgmm/common/Error.h"

namespace gpgmm {

    const char* GetErrorCodeToChar(ErrorCode errorCode) {
        switch (errorCode) {
            case ErrorCode::kNone:
                return "";
            case ErrorCode::kUnknown:
                return "UNKNOWN";
            case ErrorCode::kSizeExceeded:
                return "SIZE_EXCEEDED";
            case ErrorCode::kAllocationFailed:
                return "ALLOCATION_FAILED";
            case ErrorCode::kPrefetchFailed:
                return "PREFETCH_FAILED";
            case ErrorCode::kBudgetInvalid:
                return "BUDGET_INVALID";
            case ErrorCode::kInvalidArgument:
                return "INVALID_ARGUMENT";
            case ErrorCode::kBadOperation:
                return "BAD_OPERATION";
            default:
                UNREACHABLE();
                return "";
        }
    }

}  // namespace gpgmm
