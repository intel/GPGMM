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

#ifndef GPGMM_COMMON_MESSAGE_H_
#define GPGMM_COMMON_MESSAGE_H_

namespace gpgmm {

    enum class MessageId {
        kUnknown,
        kSizeExceeded,
        kAlignmentMismatch,
        kAllocatorFailed,
        kPrefetchFailed,
        kBudgetExceeded,
        kBudgetUpdated,
        kBudgetInvalid,
        kInvalidArgument,
        kBadOperation,
    };

    enum class MessageSeverity {
        kDebug,
        kInfo,
        kWarning,
        kError,
    };

    struct MessageInfo {
        const char* Description;
        MessageId ID;
        MessageSeverity Severity;
    };

    const char* GetMessageFromID(MessageId messageId);

}  // namespace gpgmm

#endif  // GPGMM_COMMON_MESSAGE_H_
