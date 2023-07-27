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

#ifndef SRC_GPGMM_COMMON_EVENTMESSAGE_H_
#define SRC_GPGMM_COMMON_EVENTMESSAGE_H_

#include "gpgmm/common/Message.h"
#include "gpgmm/common/Object.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Log.h"

#include <sstream>
#include <string>

namespace gpgmm {

    class EventMessage {
      public:
        EventMessage(const MessageSeverity& severity,
                     MessageId messageId,
                     bool isExternal,
                     const std::string& name,
                     const ObjectBase* object);
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
        MessageId mMessageId = MessageId::kUnknown;
        bool mIsExternal = false;
        std::string mName;
        const ObjectBase* mObject = nullptr;
        std::ostringstream mStream;
    };

    // Short-hands to create a EventMessage with the respective severity.
    EventMessage DebugEvent(MessageId messageId = MessageId::kUnknown,
                            bool isExternal = false,
                            const std::string& name = "",
                            const ObjectBase* mObject = nullptr);

    EventMessage InfoEvent(MessageId messageId = MessageId::kUnknown,
                           bool isExternal = false,
                           const std::string& name = "",
                           const ObjectBase* mObject = nullptr);

    EventMessage WarnEvent(MessageId messageId = MessageId::kUnknown,
                           bool isExternal = false,
                           const std::string& name = "",
                           const ObjectBase* mObject = nullptr);

    EventMessage ErrorEvent(MessageId messageId = MessageId::kUnknown,
                            bool isExternal = false,
                            const std::string& name = "",
                            const ObjectBase* mObject = nullptr);

    // Messages of a given severity to be recorded.
    void SetEventMessageLevel(const MessageSeverity& level);

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_EVENTMESSAGE_H_
