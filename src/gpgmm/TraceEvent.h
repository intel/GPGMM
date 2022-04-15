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

#ifndef GPGMM_TRACEEVENT_H_
#define GPGMM_TRACEEVENT_H_

#include "gpgmm/common/JSONEncoder.h"

#include <memory>
#include <string>
#include <thread>

// Trace Event Format
// https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/edit?pli=1
// Defines follow base/trace_event/common/trace_event_common.h

// clang-format off

// Phase indicates the nature of an event entry. E.g. part of a begin/end pair.
#define TRACE_EVENT_PHASE_BEGIN ('B')
#define TRACE_EVENT_PHASE_END ('E')
#define TRACE_EVENT_PHASE_INSTANT ('i')
#define TRACE_EVENT_PHASE_CREATE_OBJECT ('N')
#define TRACE_EVENT_PHASE_SNAPSHOT_OBJECT ('O')
#define TRACE_EVENT_PHASE_DELETE_OBJECT ('D')
#define TRACE_EVENT_PHASE_METADATA ('M')
#define TRACE_EVENT_PHASE_COUNTER ('C')

// Flags for changing the behavior of TRACE_EVENT_API_ADD_TRACE_EVENT.
#define TRACE_EVENT_FLAG_NONE (static_cast<unsigned char>(0))
#define TRACE_EVENT_FLAG_HAS_ID (static_cast<unsigned int>(1 << 1))
#define TRACE_EVENT_FLAG_HAS_LOCAL_ID (static_cast<unsigned int>(1 << 11))
#define TRACE_EVENT_FLAG_HAS_GLOBAL_ID (static_cast<unsigned int>(1 << 12))

#define TRACE_EMPTY do {} while (0)

#ifdef GPGMM_DISABLE_TRACING

#define TRACE_EVENT0(category_group, name) TRACE_EMPTY
#define TRACE_EVENT_INSTANT0(category_group, name, scope, args) TRACE_EMPTY
#define TRACE_COUNTER1(category_group, name, value) TRACE_EMPTY
#define TRACE_EVENT_METADATA1(category_group, name, arg1_name, arg1_value) TRACE_EMPTY

#else // !GPGMM_DISABLE_TRACING

// Specify these values when the corresponding argument of AddTraceEvent
// is not used.
const uint64_t kNoId = 0;

// Records a pair of begin and end events called "name" for the current scope.
// Name parameter must have program lifetime (statics or literals).
#define TRACE_EVENT0(category_group, name) INTERNAL_TRACE_EVENT_ADD_SCOPED(category_group, name)

// Records information related to other events.
#define TRACE_EVENT_METADATA1(category_group, name, arg1_name, arg1_value) \
    INTERNAL_TRACE_EVENT_METADATA_ADD(category_group, name, arg1_name, arg1_value)

#define TRACE_COUNTER1(category_group, name, value)                                                           \
    INTERNAL_TRACE_EVENT_ADD(TRACE_EVENT_PHASE_COUNTER, category_group, name, TRACE_EVENT_FLAG_NONE, "value", \
                             static_cast<int>(value))

#define TRACE_EVENT_INSTANT1(category_group, name, args) \
    INTERNAL_TRACE_EVENT_ADD(TRACE_EVENT_PHASE_INSTANT, category_group, name, TRACE_EVENT_FLAG_NONE, args)

#define TRACE_EVENT_BEGIN0(category_group, name) \
    INTERNAL_TRACE_EVENT_ADD(TRACE_EVENT_PHASE_BEGIN, category_group, name, TRACE_EVENT_FLAG_NONE)

#define TRACE_EVENT_END0(category_group, name) \
    INTERNAL_TRACE_EVENT_ADD(TRACE_EVENT_PHASE_END, category_group, name, TRACE_EVENT_FLAG_NONE)

#define TRACE_EVENT_OBJECT_CREATED_WITH_ID(category_group, name, id)                            \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_CREATE_OBJECT, category_group, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID)

#define TRACE_EVENT_OBJECT_DELETED_WITH_ID(category_group, name, id)                            \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_DELETE_OBJECT, category_group, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID)

#define TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(category_group, name, id, snapshot)                   \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_SNAPSHOT_OBJECT, category_group, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID, "snapshot", snapshot)

#define INTERNAL_TRACE_EVENT_METADATA_ADD(category_group, name, ...)      \
    INTERNAL_TRACE_EVENT_ADD(TRACE_EVENT_PHASE_METADATA, category_group,  \
                             name, TRACE_EVENT_FLAG_NONE, __VA_ARGS__)

#define INTERNAL_TRACE_EVENT_ADD_SCOPED(category_group, name) \
    struct ScopedTraceEvent {                                 \
        ScopedTraceEvent() {                                  \
            TRACE_EVENT_BEGIN0(category_group, name);         \
        }                                                     \
        ~ScopedTraceEvent() {                                 \
            TRACE_EVENT_END0(category_group, name);           \
        }                                                     \
    } scopedTraceEvent {                                      \
    }

#define INTERNAL_TRACE_EVENT_ADD_WITH_ID(phase, category_group, name, id, ...)           \
    do {                                                                                 \
        gpgmm::TraceBuffer::AddTraceEvent(phase, category_group, name,                   \
                                          gpgmm::TraceEventID(id).GetID(), __VA_ARGS__); \
    } while (false)

#define INTERNAL_TRACE_EVENT_ADD(phase, category_group, name, ...)             \
    do {                                                                       \
        gpgmm::TraceBuffer::AddTraceEvent(phase, category_group, name, kNoId,  \
                                          __VA_ARGS__);                        \
    } while (false)

#endif

namespace gpgmm {

    enum TraceEventCategory {
        Default = 0,
        Metadata = 1,
    };

    class EventTraceWriter;
    class PlatformTime;

    void StartupEventTrace(const std::string& traceFile,
                           bool skipDurationEvents,
                           bool skipObjectEvents,
                           bool skipInstantEvents);

    bool IsEventTraceEnabled();

    class TraceEventID {
      public:
        explicit TraceEventID(const void* id)
            : mID(static_cast<uint64_t>(reinterpret_cast<uintptr_t>(id))) {
        }

        explicit TraceEventID(uint64_t id) : mID(id) {
        }

        uint64_t GetID() const {
            return mID;
        }

        static constexpr const char* kIdRefKey = "id_ref";

      private:
        uint64_t mID;
    };

    class TraceEvent {
      public:
        TraceEvent(char phase,
                   TraceEventCategory category,
                   const char* name,
                   uint64_t id,
                   uint32_t tid,
                   double timestamp,
                   uint32_t flags,
                   const JSONDict& args);

      private:
        friend EventTraceWriter;

        char mPhase = 0;
        TraceEventCategory mCategory;
        const char* mName = nullptr;
        uint64_t mID = 0;
        uint32_t mTID = 0;
        double mTimestamp = 0;
        uint32_t mFlags = 0;
        JSONDict mArgs;
    };

    class TraceBuffer {
      public:
        static void AddTraceEvent(char phase,
                                  TraceEventCategory category,
                                  const char* name,
                                  uint64_t id,
                                  uint32_t flags,
                                  const JSONDict& args = {});

        template <class Arg1T>
        static void AddTraceEvent(char phase,
                                  TraceEventCategory category,
                                  const char* name,
                                  uint64_t id,
                                  uint32_t flags,
                                  const char* arg1Name,
                                  const Arg1T& arg1Value) {
            JSONDict args = {};
            args.AddItem(arg1Name, arg1Value);
            AddTraceEvent(phase, category, name, id, flags, args);
        }
    };

}  // namespace gpgmm

#endif  // GPGMM_TRACEEVENT_H_
