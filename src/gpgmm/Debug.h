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

#ifndef GPGMM_DEBUG_H_
#define GPGMM_DEBUG_H_

#include "gpgmm/JSONSerializer.h"
#include "gpgmm/TraceEvent.h"
#include "gpgmm/common/Log.h"

#include <sstream>
#include <string>

namespace gpgmm {

    struct LOG_MESSAGE {
        std::string Description;
        int ID;
    };

#define GPGMM_TRACE_EVENT_OBJECT_NEW(objPtr)                                                     \
    do {                                                                                         \
        TRACE_EVENT_OBJECT_CREATED_WITH_ID(TraceEventCategory::Default, (*objPtr).GetTypename(), \
                                           objPtr);                                              \
    } while (false)

#define GPGMM_TRACE_EVENT_OBJECT_DESTROY(objPtr)                                                 \
    do {                                                                                         \
        TRACE_EVENT_OBJECT_DELETED_WITH_ID(TraceEventCategory::Default, (*objPtr).GetTypename(), \
                                           objPtr);                                              \
    } while (false)

#define GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(objPtr, desc)                                           \
    do {                                                                                          \
        TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(TraceEventCategory::Default, (*objPtr).GetTypename(), \
                                            objPtr,                                               \
                                            GPGMM_LAZY_SERIALIZE(desc, IsEventTraceEnabled()));   \
    } while (false)

#define GPGMM_TRACE_EVENT_OBJECT_CALL(name, desc)                               \
    do {                                                                        \
        TRACE_EVENT_INSTANT(TraceEventCategory::Default, name,                  \
                            GPGMM_LAZY_SERIALIZE(desc, IsEventTraceEnabled())); \
    } while (false)

    class EventMessage : public LogMessage {
      public:
        EventMessage(const LogSeverity& level, const char* name, int messageId = 0);
        ~EventMessage();

        EventMessage(EventMessage&& other) = default;
        EventMessage& operator=(EventMessage&& other) = default;

        template <typename T>
        EventMessage& operator<<(T&& value) {
            mStream << value;
            return *this;
        }

      private:
        LogSeverity mSeverity;
        const char* mName = nullptr;
        int mMessageId = 0;

        std::ostringstream mStream;
    };

    EventMessage DebugEvent(const char* name, int messageId = 0);
    EventMessage InfoEvent(const char* name, int messageId = 0);
    EventMessage WarningEvent(const char* name, int messageId = 0);
    EventMessage ErrorEvent(const char* name, int messageId = 0);

    // Messages of a given severity to be recorded.
    void SetEventMessageLevel(const LogSeverity& level);

// Helper macro to avoid evaluating the arguments when the condition doesn't hold.
#define GPGMM_LAZY_SERIALIZE(object, condition) \
    !(condition) ? JSONSerializer::Serialize() : JSONSerializer::Serialize(object)

}  // namespace gpgmm

#endif  // GPGMM_DEBUG_H_
