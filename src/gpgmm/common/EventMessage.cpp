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

    LogSeverity GetDefaultEventMessageLevel() {
#if defined(NDEBUG)
        return LogSeverity::Info;
#else
        return LogSeverity::Debug;
#endif  // defined(NDEBUG)
    }

    // Messages with equal or greater to severity will be logged.
    static LogSeverity gRecordEventLevel = GetDefaultEventMessageLevel();
    static std::mutex mMutex;

    void SetEventMessageLevel(const LogSeverity& newLevel) {
        std::lock_guard<std::mutex> lock(mMutex);
        gRecordEventLevel = newLevel;
    }

    LogSeverity GetEventMessageLevel() {
        std::lock_guard<std::mutex> lock(mMutex);
        return gRecordEventLevel;
    }

    // EventMessage

    EventMessage::EventMessage(const LogSeverity& level,
                               const char* name,
                               const void* object,
                               EventMessageId messageId)
        : mSeverity(level), mName(name), mObject(object), mMessageId(messageId) {
    }

    EventMessage::~EventMessage() {
        const std::string description = mStream.str();

        gpgmm::Log(mSeverity) << mName << "=" << ToString(mObject) << ": " << description << " ("
                              << static_cast<int>(mMessageId) << ")";

#if defined(GPGMM_ENABLE_ASSERT_ON_WARNING)
        ASSERT(mSeverity < LogSeverity::Warning);
#endif

        if (mSeverity >= GetEventMessageLevel()) {
            EventMessageInfo message{description, mMessageId};
            GPGMM_TRACE_EVENT_OBJECT_CALL(mName, message);
        }
    }

    EventMessage DebugEvent(const ObjectBase* object, EventMessageId messageId) {
        return {LogSeverity::Debug, object->GetTypename(), object, messageId};
    }

    EventMessage InfoEvent(const ObjectBase* object, EventMessageId messageId) {
        return {LogSeverity::Info, object->GetTypename(), object, messageId};
    }

    EventMessage WarnEvent(const ObjectBase* object, EventMessageId messageId) {
        return {LogSeverity::Warning, object->GetTypename(), object, messageId};
    }

    EventMessage ErrorEvent(const ObjectBase* object, EventMessageId messageId) {
        return {LogSeverity::Error, object->GetTypename(), object, messageId};
    }

}  // namespace gpgmm
