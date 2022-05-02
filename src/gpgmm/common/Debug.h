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

#ifndef GPGMM_COMMON_DEBUG_H_
#define GPGMM_COMMON_DEBUG_H_

#include "gpgmm/common/JSONSerializer.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Log.h"

#include <sstream>
#include <string>

#ifdef GPGMM_DISABLE_TRACING

#    define GPGMM_TRACE_EVENT_OBJECT_NEW(objPtr) TRACE_EMPTY
#    define GPGMM_TRACE_EVENT_OBJECT_DESTROY(objPtr) TRACE_EMPTY
#    define GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(objPtr, desc) TRACE_EMPTY
#    define GPGMM_TRACE_EVENT_OBJECT_CALL(name, desc) TRACE_EMPTY

#else  // !GPGMM_DISABLE_TRACING

#    define GPGMM_TRACE_EVENT_OBJECT_NEW(objPtr)                                 \
        do {                                                                     \
            TRACE_EVENT_OBJECT_CREATED_WITH_ID(TraceEventCategory::Default,      \
                                               (*objPtr).GetTypename(), objPtr); \
        } while (false)

#    define GPGMM_TRACE_EVENT_OBJECT_DESTROY(objPtr)                             \
        do {                                                                     \
            TRACE_EVENT_OBJECT_DELETED_WITH_ID(TraceEventCategory::Default,      \
                                               (*objPtr).GetTypename(), objPtr); \
        } while (false)

#    define GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(objPtr, desc)                   \
        do {                                                                  \
            TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(                              \
                TraceEventCategory::Default, (*objPtr).GetTypename(), objPtr, \
                GPGMM_LAZY_SERIALIZE(desc, IsEventTraceEnabled()));           \
        } while (false)

#    define GPGMM_TRACE_EVENT_OBJECT_CALL(name, desc)                                \
        do {                                                                         \
            TRACE_EVENT_INSTANT1(TraceEventCategory::Default, name,                  \
                                 GPGMM_LAZY_SERIALIZE(desc, IsEventTraceEnabled())); \
        } while (false)

// Helper macro to avoid evaluating the arguments when the condition doesn't hold.
#    define GPGMM_LAZY_SERIALIZE(object, condition) \
        !(condition) ? JSONSerializer::Serialize() : JSONSerializer::Serialize(object)

#endif  // GPGMM_DISABLE_TRACING

namespace gpgmm {

    struct LOG_MESSAGE {
        std::string Description;
        int ID;
    };

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
    EventMessage WarnEvent(const char* name, int messageId = 0);
    EventMessage ErrorEvent(const char* name, int messageId = 0);

    // Messages of a given severity to be recorded.
    void SetEventMessageLevel(const LogSeverity& level);

}  // namespace gpgmm

#endif  // GPGMM_COMMON_DEBUG_H_
