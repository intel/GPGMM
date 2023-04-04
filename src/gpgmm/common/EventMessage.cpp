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

#include "gpgmm/common/EventMessage.h"

#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Utils.h"

#include <mutex>

namespace gpgmm {

    MessageSeverity GetDefaultEventMessageLevel() {
#if defined(NDEBUG)
        return MessageSeverity::kInfo;
#else
        return MessageSeverity::kDebug;
#endif  // defined(NDEBUG)
    }

    // Messages with equal or greater to severity will be logged.
    static MessageSeverity gRecordEventLevel = GetDefaultEventMessageLevel();
    static std::mutex mMutex;

    void SetEventMessageLevel(const MessageSeverity& newLevel) {
        std::lock_guard<std::mutex> lock(mMutex);
        gRecordEventLevel = newLevel;
    }

    MessageSeverity GetEventMessageLevel() {
        std::lock_guard<std::mutex> lock(mMutex);
        return gRecordEventLevel;
    }

    // EventMessage

    EventMessage::EventMessage(const MessageSeverity& severity,
                               MessageId messageId,
                               const ObjectBase* object)
        : mSeverity(severity), mMessageId(messageId), mObject(object) {
    }

    EventMessage::~EventMessage() {
        const std::string description = mStream.str();

        gpgmm::Log(mSeverity, mMessageId, mObject) << description;

#if defined(GPGMM_ENABLE_ASSERT_ON_WARNING)
        ASSERT(mSeverity < MessageSeverity::kWarning);
#endif

        if (mSeverity >= GetEventMessageLevel() && mObject != nullptr) {
            GPGMM_TRACE_EVENT_OBJECT_CALL(
                mObject->GetTypename(), MessageInfo({description.c_str(), mMessageId, mSeverity}));
        }
    }

    EventMessage DebugEvent(MessageId messageId, const ObjectBase* object) {
        return {MessageSeverity::kDebug, messageId, object};
    }

    EventMessage InfoEvent(MessageId messageId, const ObjectBase* object) {
        return {MessageSeverity::kInfo, messageId, object};
    }

    EventMessage WarnEvent(MessageId messageId, const ObjectBase* object) {
        return {MessageSeverity::kWarning, messageId, object};
    }

    EventMessage ErrorEvent(MessageId messageId, const ObjectBase* object) {
        return {MessageSeverity::kError, messageId, object};
    }

}  // namespace gpgmm
