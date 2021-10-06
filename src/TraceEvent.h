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

#include <memory>
#include <string>
#include <vector>

// Trace Event Format
// https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/edit?pli=1
// Defines follow base/trace_event/common/trace_event_common.h

// Phase indicates the nature of an event entry. E.g. part of a begin/end pair.
#define TRACE_EVENT_PHASE_BEGIN ('B')
#define TRACE_EVENT_PHASE_END ('E')
#define TRACE_EVENT_PHASE_INSTANT ('i')
#define TRACE_EVENT_PHASE_CREATE_OBJECT ('N')
#define TRACE_EVENT_PHASE_SNAPSHOT_OBJECT ('O')
#define TRACE_EVENT_PHASE_DELETE_OBJECT ('D')

// Flags for changing the behavior of TRACE_EVENT_API_ADD_TRACE_EVENT.
#define TRACE_EVENT_FLAG_NONE (static_cast<unsigned char>(0))
#define TRACE_EVENT_FLAG_HAS_ID (static_cast<unsigned int>(1 << 1))
#define TRACE_EVENT_FLAG_HAS_LOCAL_ID (static_cast<unsigned int>(1 << 11))
#define TRACE_EVENT_FLAG_HAS_GLOBAL_ID (static_cast<unsigned int>(1 << 12))

// Specify these values when the corresponding argument of AddTraceEvent
// is not used.
const uint64_t kNoId = 0;

#define GPGMM_API_TRACE_FUNCTION_CALL(DESC)                                \
    do {                                                                   \
        if (gpgmm::IsEventTracerEnabled()) {                               \
            auto GPGMM_LOCAL_ARGS = JSONSerializer::SerializeToJSON(DESC); \
            TRACE_EVENT_INSTANT(__func__, GPGMM_LOCAL_ARGS);               \
        }                                                                  \
    } while (false)

#define GPGMM_OBJECT_NEW_INSTANCE(className)                     \
    do {                                                         \
        if (gpgmm::IsEventTracerEnabled()) {                     \
            TRACE_EVENT_OBJECT_CREATED_WITH_ID(className, this); \
        }                                                        \
    } while (false)

#define GPGMM_OBJECT_DELETE_INSTANCE(className)                  \
    do {                                                         \
        if (gpgmm::IsEventTracerEnabled()) {                     \
            TRACE_EVENT_OBJECT_CREATED_WITH_ID(className, this); \
        }                                                        \
    } while (false)

#define TRACE_EVENT_INSTANT(name, args) \
    INTERNAL_TRACE_EVENT_ADD_WITH_ARGS(TRACE_EVENT_PHASE_INSTANT, name, TRACE_EVENT_FLAG_NONE, args)

#define TRACE_EVENT_START(name) \
    INTERNAL_TRACE_EVENT_ADD(TRACE_EVENT_PHASE_BEGIN, name, TRACE_EVENT_FLAG_NONE)

#define TRACE_EVENT_END(name) \
    INTERNAL_TRACE_EVENT_ADD(TRACE_EVENT_PHASE_END, name, TRACE_EVENT_FLAG_NONE)

#define TRACE_EVENT_OBJECT_CREATED_WITH_ID(name, id)                            \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_CREATE_OBJECT, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID)

#define TRACE_EVENT_OBJECT_DELETED_WITH_ID(name, id)                            \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_DELETE_OBJECT, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID)

#define TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(name, id)                             \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_SNAPSHOT_OBJECT, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID)

#define INTERNAL_TRACE_EVENT_ADD(phase, name, flags)                   \
    do {                                                               \
        gpgmm::EventTracing::AddTraceEvent(phase, name, kNoId, flags); \
    } while (false)

#define INTERNAL_TRACE_EVENT_ADD_WITH_ID(phase, name, id, flags)                      \
    do {                                                                              \
        gpgmm::TraceEventID traceEventID(id);                                         \
        gpgmm::EventTracing::AddTraceEvent(phase, name, traceEventID.GetID(), flags); \
    } while (false)

#define INTERNAL_TRACE_EVENT_ADD_WITH_ARGS(phase, name, flags, args)         \
    do {                                                                     \
        gpgmm::EventTracing::AddTraceEvent(phase, name, kNoId, flags, args); \
    } while (false)

namespace gpgmm {

    enum TraceEventCategory {
        Default = 0,
    };

    class EventTracer;
    class PlatformTime;

    void StartupEventTracer(const char* eventTraceFile);
    void ShutdownEventTracer();

    bool IsEventTracerEnabled();

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

      private:
        uint64_t mID;
    };

    class TraceEvent {
      public:
        TraceEvent(char phase,
                   TraceEventCategory category,
                   const char* name,
                   uint64_t id,
                   double timestamp,
                   uint32_t flags,
                   std::string args);
        ~TraceEvent() = default;

      private:
        friend EventTracer;

        char mPhase = 0;
        TraceEventCategory mCategory;
        const char* mName = nullptr;
        uint64_t mID = 0;
        std::string mThreadId;
        double mTimestamp = 0;
        uint32_t mFlags = TRACE_EVENT_FLAG_NONE;
        std::string mArgs;
    };

    class EventTracing {
      public:
        static void AddTraceEvent(char phase,
                                  const char* name,
                                  uint64_t id,
                                  uint32_t flags,
                                  std::string args = "");
    };

    class EventTracer {
      public:
        EventTracer(const char* traceFile);
        ~EventTracer();

        void EnqueueTraceEvent(char phase,
                               const char* name,
                               uint64_t id,
                               uint32_t flags,
                               std::string args);
        void FlushQueuedEventsToDisk();

      private:
        std::vector<TraceEvent> mTraceEventQueue;
        const char* mTraceFile = nullptr;
        std::unique_ptr<PlatformTime> mPlatformTime;
    };

}  // namespace gpgmm

#endif  // GPGMM_TRACEEVENT_H_
