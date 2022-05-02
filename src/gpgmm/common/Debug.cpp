// Copyright 2021 The GPGMM Authors
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

#include "gpgmm/common/Debug.h"

#include "gpgmm/utils/Assert.h"
#include "gpgmm/utils/Log.h"

namespace gpgmm {
    // Messages with equal or greater to severity will be logged.
    LogSeverity gRecordEventLevel = LogSeverity::Info;

    void SetEventMessageLevel(const LogSeverity& newLevel) {
        gRecordEventLevel = newLevel;
    }

    EventMessage::EventMessage(const LogSeverity& level, const char* name, int messageId)
        : LogMessage(level), mSeverity(level), mName(name), mMessageId(messageId) {
    }

    EventMessage::~EventMessage() {
        const std::string description = mStream.str();

        gpgmm::Log(mSeverity) << mName << ": " << description;
#if defined(GPGMM_ENABLE_ASSERT_ON_WARNING)
        ASSERT(mSeverity < LogSeverity::Warning);
#endif
        if (mSeverity >= gRecordEventLevel) {
            LOG_MESSAGE message{description, mMessageId};
            GPGMM_TRACE_EVENT_OBJECT_CALL(mName, message);
        }
    }

    EventMessage DebugEvent(const char* name, int messageId) {
        return {LogSeverity::Debug, name, messageId};
    }

    EventMessage InfoEvent(const char* name, int messageId) {
        return {LogSeverity::Info, name, messageId};
    }

    EventMessage WarnEvent(const char* name, int messageId) {
        return {LogSeverity::Warning, name, messageId};
    }

    EventMessage ErrorEvent(const char* name, int messageId) {
        return {LogSeverity::Error, name, messageId};
    }

}  // namespace gpgmm
