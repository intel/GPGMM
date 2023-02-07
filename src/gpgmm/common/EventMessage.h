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

#ifndef GPGMM_COMMON_EVENT_MESSAGE_H_
#define GPGMM_COMMON_EVENT_MESSAGE_H_

#include "gpgmm/common/Message.h"
#include "gpgmm/common/Object.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Log.h"

#include <sstream>
#include <string>

namespace gpgmm {

    class EventMessage {
      public:
        EventMessage(const MessageSeverity& level,
                     const char* name,
                     const void* object,
                     MessageId messageId = MessageId::kUnknown);
        ~EventMessage();

        EventMessage(EventMessage&& other) = default;
        EventMessage& operator=(EventMessage&& other) = default;

        template <typename T>
        EventMessage& operator<<(T&& value) {
            mStream << value;
            return *this;
        }

      private:
        MessageSeverity mSeverity;
        const char* mName = nullptr;
        const void* mObject = nullptr;
        MessageId mMessageId = MessageId::kUnknown;

        std::ostringstream mStream;
    };

    EventMessage DebugEvent(const ObjectBase* object, MessageId messageId = MessageId::kUnknown);

    EventMessage InfoEvent(const ObjectBase* object, MessageId messageId = MessageId::kUnknown);

    EventMessage WarnEvent(const ObjectBase* object, MessageId messageId = MessageId::kUnknown);

    EventMessage ErrorEvent(const ObjectBase* object, MessageId messageId = MessageId::kUnknown);

    // Messages of a given severity to be recorded.
    void SetEventMessageLevel(const MessageSeverity& level);

}  // namespace gpgmm

#endif  // GPGMM_COMMON_EVENT_MESSAGE_H_
