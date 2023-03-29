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

#include "Message.h"

#include "gpgmm/utils/Assert.h"

namespace gpgmm {

    const char* GetMessageFromID(MessageId messageId) {
        switch (messageId) {
            case MessageId::kUnknown:
                return "UNKNOWN";
            case MessageId::kSizeExceeded:
                return "SIZE_EXCEEDED";
            case MessageId::kAlignmentMismatch:
                return "ALIGNMENT_MISMATCH";
            case MessageId::kAllocatorFailed:
                return "ALLOCATOR_FAILED";
            case MessageId::kPrefetchFailed:
                return "PREFETCH_FAILED";
            case MessageId::kBudgetExceeded:
                return "BUDGET_EXCEEDED";
            case MessageId::kBudgetUpdated:
                return "BUDGET_UPDATED";
            case MessageId::kBudgetInvalid:
                return "BUDGET_INVALID";
            case MessageId::kInvalidArgument:
                return "INVALID_ARGUMENT";
            case MessageId::kBadOperation:
                return "BAD_OPERATION";
            case MessageId::kPerformanceWarning:
                return "PERFORMANCE_WARNING";
            case MessageId::kMemoryUsageUpdated:
                return "MEMORY_USAGE_UPDATED";
            case MessageId::kMemoryAllocated:
                return "MEMORY_CREATED";
            default:
                UNREACHABLE();
                return "";
        }
    }

}  // namespace gpgmm
