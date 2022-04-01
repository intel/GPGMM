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
#include "gpgmm/common/Utils.h"

#include <memory>
#include <string>
#include <thread>
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

#define TRACE_EVENT_CURRENT_THREAD_ID std::stoi(ToString(std::this_thread::get_id()))

// Specify these values when the corresponding argument of AddTraceEvent
// is not used.
const uint64_t kNoId = 0;

#define TRACE_EVENT_CALL_SCOPED(name) \
    struct ScopedTracedCall {         \
        ScopedTracedCall() {          \
            TRACE_EVENT_BEGIN(name);  \
        }                             \
        ~ScopedTracedCall() {         \
            TRACE_EVENT_END(name);    \
        }                             \
    } scopedTracedCall {              \
    }

#define TRACE_EVENT_INSTANT(name, args)                                      \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_INSTANT, name, kNoId, \
                                     TRACE_EVENT_FLAG_NONE, args)

#define TRACE_EVENT_BEGIN(name) \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_BEGIN, name, kNoId, TRACE_EVENT_FLAG_NONE)

#define TRACE_EVENT_END(name) \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_END, name, kNoId, TRACE_EVENT_FLAG_NONE)

#define TRACE_EVENT_OBJECT_CREATED_WITH_ID(name, id)                            \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_CREATE_OBJECT, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID)

#define TRACE_EVENT_OBJECT_DELETED_WITH_ID(name, id)                            \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_DELETE_OBJECT, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID)

#define TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(name, id, snapshot)                   \
    INTERNAL_TRACE_EVENT_ADD_WITH_ID(TRACE_EVENT_PHASE_SNAPSHOT_OBJECT, name, id, \
                                     TRACE_EVENT_FLAG_HAS_ID, {"snapshot", snapshot})

#define INTERNAL_TRACE_EVENT_ADD_WITH_ID(phase, name, id, ...)                          \
    do {                                                                                \
        gpgmm::EventTracer::AddTraceEvent(phase, name, gpgmm::TraceEventID(id).GetID(), \
                                          TRACE_EVENT_CURRENT_THREAD_ID, __VA_ARGS__);  \
    } while (false)

namespace gpgmm {

    enum TraceEventCategory {
        Default = 0,
    };

    class FileEventTracer;
    class PlatformTime;

    void StartupEventTracer(const std::string& traceFile,
                            bool skipDurationEvents,
                            bool skipObjectEvents,
                            bool skipInstantEvents);
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
        friend FileEventTracer;

        char mPhase = 0;
        TraceEventCategory mCategory;
        const char* mName = nullptr;
        uint64_t mID = 0;
        uint32_t mTID = 0;
        double mTimestamp = 0;
        uint32_t mFlags = TRACE_EVENT_FLAG_NONE;
        JSONDict mArgs;
    };

    class EventTracer {
      public:
        static void AddTraceEvent(char phase,
                                  const char* name,
                                  uint64_t id,
                                  uint32_t tid,
                                  uint32_t flags,
                                  const JSONDict& args = {});
    };

    class FileEventTracer {
      public:
        explicit FileEventTracer(const std::string& traceFile,
                                 bool skipDurationEvents,
                                 bool skipObjectEvents,
                                 bool skipInstantEvents);
        ~FileEventTracer();

        void EnqueueTraceEvent(char phase,
                               const char* name,
                               uint64_t id,
                               uint32_t tid,
                               uint32_t flags,
                               const JSONDict& args);
        void FlushQueuedEventsToDisk();

      private:
        std::vector<TraceEvent> mQueue;
        std::string mTraceFile;
        std::unique_ptr<PlatformTime> mPlatformTime;

        bool mSkipDurationEvents = false;
        bool mSkipObjectEvents = false;
        bool mSkipInstantEvents = false;
    };

}  // namespace gpgmm

#endif  // GPGMM_TRACEEVENT_H_
