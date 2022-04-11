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

#include <string>

namespace gpgmm {

    static std::unique_ptr<EventTraceWriter> gEventTrace;

    void StartupEventTrace(const std::string& traceFile,
                           bool skipDurationEvents,
                           bool skipObjectEvents,
                           bool skipInstantEvents) {
        if (gEventTrace == nullptr) {
            gEventTrace = std::make_unique<EventTraceWriter>(traceFile, skipDurationEvents,
                                                           skipObjectEvents, skipInstantEvents);

            InitializeThreadName("GPGMM_MainThread");
        }
    }

    void InitializeThreadName(const char* name) {
        JSONDict args;
        args.AddItem("name", name);
        TRACE_EVENT_METADATA("thread_name", args);
    }

    void ShutdownEventTrace() {
#if !defined(GPGMM_ENABLE_RECORDING_UNTIL_TERMINATION)
        gEventTrace = nullptr;
#endif
    }

    bool IsEventTraceEnabled() {
        return (gEventTrace != nullptr);
    }

    TraceEvent::TraceEvent(char phase,
                           TraceEventCategory category,
                           const char* name,
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
                                    uint32_t tid,
                                    uint32_t flags,
                                    const JSONDict& args) {
        if (gEventTrace != nullptr) {
            gEventTrace->EnqueueTraceEvent(phase, category, name, id, tid, flags, args);
        }
    }
}  // namespace gpgmm
