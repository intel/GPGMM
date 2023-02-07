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
        return MessageSeverity::Info;
#else
        return MessageSeverity::Debug;
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

    EventMessage::EventMessage(const MessageSeverity& level,
                               const char* name,
                               const void* object,
                               MessageId messageId)
        : mSeverity(level), mName(name), mObject(object), mMessageId(messageId) {
    }

    EventMessage::~EventMessage() {
        const std::string description = mStream.str();

        gpgmm::Log(mSeverity) << mName << "=" << ToString(mObject) << ": " << description << " ("
                              << static_cast<int>(mMessageId) << ")";

#if defined(GPGMM_ENABLE_ASSERT_ON_WARNING)
        ASSERT(mSeverity < MessageSeverity::Warning);
#endif

        if (mSeverity >= GetEventMessageLevel()) {
            MessageInfo message{description, mMessageId};
            GPGMM_TRACE_EVENT_OBJECT_CALL(mName, message);
        }
    }

    EventMessage DebugEvent(const ObjectBase* object, MessageId messageId) {
        return {MessageSeverity::Debug, object->GetTypename(), object, messageId};
    }

    EventMessage InfoEvent(const ObjectBase* object, MessageId messageId) {
        return {MessageSeverity::Info, object->GetTypename(), object, messageId};
    }

    EventMessage WarnEvent(const ObjectBase* object, MessageId messageId) {
        return {MessageSeverity::Warning, object->GetTypename(), object, messageId};
    }

    EventMessage ErrorEvent(const ObjectBase* object, MessageId messageId) {
        return {MessageSeverity::Error, object->GetTypename(), object, messageId};
    }

}  // namespace gpgmm
