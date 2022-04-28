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

#include "gpgmm/TraceEvent.h"

#include "gpgmm/EventTraceWriter.h"

#include <mutex>
#include <string>

namespace gpgmm {

    static std::unique_ptr<EventTraceWriter> gEventTrace;
    static std::mutex mMutex;

    static EventTraceWriter* GetInstance() {
        std::lock_guard<std::mutex> lock(mMutex);
        if (gEventTrace == nullptr) {
            gEventTrace = std::make_unique<EventTraceWriter>();
        }
        return gEventTrace.get();
    }

    void StartupEventTrace(const std::string& traceFile,
                           bool skipDurationEvents,
                           bool skipObjectEvents,
                           bool skipInstantEvents) {
        TRACE_EVENT_METADATA1(TraceEventCategory::Metadata, "thread_name", "name",
                              "GPGMM_MainThread");

        GetInstance()->SetConfiguration(traceFile, skipDurationEvents, skipObjectEvents,
                                        skipInstantEvents);
    }

    void ShutdownEventTrace() {
        GetInstance()->FlushQueuedEventsToDisk();
    }

    bool IsEventTraceEnabled() {
        std::lock_guard<std::mutex> lock(mMutex);
        return gEventTrace != nullptr;
    }

    TraceEvent::TraceEvent(char phase,
                           TraceEventCategory category,
                           const std::string& name,
                           uint64_t id,
                           uint32_t tid,
                           double timestamp,
                           uint32_t flags,
                           const JSONDict& args)
        : mPhase(phase),
          mCategory(category),
          mName(name),
          mID(id),
          mTID(tid),
          mTimestamp(timestamp),
          mFlags(flags),
          mArgs(args) {
    }

    void TraceBuffer::AddTraceEvent(char phase,
                                    TraceEventCategory category,
                                    const char* name,
                                    uint64_t id,
                                    uint32_t flags,
                                    const JSONDict& args) {
        if (IsEventTraceEnabled()) {
            GetInstance()->EnqueueTraceEvent(phase, category, name, id, flags, args);
        }
    }
}  // namespace gpgmm
