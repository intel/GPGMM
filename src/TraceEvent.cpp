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

#include "src/TraceEvent.h"
#include "common/Assert.h"
#include "common/PlatformTime.h"

#include <fstream>
#include <sstream>
#include <thread>

static constexpr const char* kDefaultTraceFile = "trace.json";

namespace gpgmm {

    EventTracer* gEventTracer = nullptr;

    void StartupEventTracer(const char* eventTraceFile) {
        gEventTracer =
            new EventTracer((eventTraceFile != nullptr) ? eventTraceFile : kDefaultTraceFile);
    }

    void ShutdownEventTracer() {
        if (gEventTracer != nullptr) {
            delete gEventTracer;
            gEventTracer = nullptr;
        }
    }

    bool IsEventTracerEnabled() {
        return (gEventTracer != nullptr);
    }

    TraceEvent::TraceEvent(char phase,
                           TraceEventCategory category,
                           const char* name,
                           uint64_t id,
                           double timestamp,
                           uint32_t flags,
                           std::string args)
        : mPhase(phase),
          mCategory(category),
          mName(name),
          mID(id),
          mTimestamp(timestamp),
          mFlags(flags),
          mArgs(args) {
    }

    void EventTracing::AddTraceEvent(char phase,
                                     const char* name,
                                     uint64_t id,
                                     uint32_t flags,
                                     std::string args) {
        if (gEventTracer != nullptr) {
            gEventTracer->EnqueueTraceEvent(phase, name, id, flags, args);
        }
    }

    EventTracer::EventTracer(const char* traceFile)
        : mTraceFile(traceFile), mPlatformTime(CreatePlatformTime()) {
        if (mTraceFile != nullptr) {
            std::ofstream outFile;
            outFile.open(mTraceFile);
            outFile << "{ \"traceEvents\": [";
            outFile << "{}";  // Dummy object so trace events can always prepend a comma
            outFile.flush();
            outFile.close();
        }
    }

    EventTracer::~EventTracer() {
        if (mTraceFile != nullptr) {
            FlushQueuedEventsToDisk();

            std::ofstream outFile;
            outFile.open(mTraceFile, std::ios_base::app);
            outFile << "]}";
            outFile << std::endl;
            outFile.close();
        }
    }

    void EventTracer::EnqueueTraceEvent(char phase,
                                        const char* name,
                                        uint64_t id,
                                        uint32_t flags,
                                        std::string args) {
        const double timestamp = mPlatformTime->GetRelativeTime();
        if (timestamp != 0) {
            mTraceEventQueue.push_back(
                {phase, TraceEventCategory::Default, name, id, timestamp, flags, args});
        }
    }

    void EventTracer::FlushQueuedEventsToDisk() {
        std::ofstream outFile;
        outFile.open(mTraceFile, std::ios_base::app);

        for (const TraceEvent& traceEvent : mTraceEventQueue) {
            // TODO: Support per thread event tracing via traceEvent.mThread.
            outFile << ", { "
                    << "\"name\": \"" << traceEvent.mName << "\", "
                    << "\"cat\": \"" << traceEvent.mCategory << "\", "
                    << "\"ph\": \"" << traceEvent.mPhase << "\", ";

            const uint32_t idFlags =
                traceEvent.mFlags & (TRACE_EVENT_FLAG_HAS_ID | TRACE_EVENT_FLAG_HAS_LOCAL_ID |
                                     TRACE_EVENT_FLAG_HAS_GLOBAL_ID);

            if (idFlags) {
                std::stringstream traceEventID;
                traceEventID << std::hex << static_cast<uint64_t>(traceEvent.mID);

                switch (idFlags) {
                    case TRACE_EVENT_FLAG_HAS_ID:
                        outFile << "\"id\":\"0x" << traceEventID.str() << "\", ";
                        break;

                    case TRACE_EVENT_FLAG_HAS_LOCAL_ID:
                        outFile << "\"id2\":{\"local\":\"0x" << traceEventID.str() << "\"}, ";
                        break;

                    case TRACE_EVENT_FLAG_HAS_GLOBAL_ID:
                        outFile << "\"id2\":{\"global\":\"0x" << traceEventID.str() << "\"}, ";
                        break;

                    default:
                        UNREACHABLE();
                        break;
                }
            }

            const uint64_t microseconds =
                static_cast<uint64_t>(traceEvent.mTimestamp * 1000.0 * 1000.0);
            outFile << "\"tid\": " << std::this_thread::get_id() << ", "
                    << "\"ts\": " << microseconds << ", "
                    << "\"pid\": \"GPGMM\"";

            if (!traceEvent.mArgs.empty()) {
                outFile << ", "
                        << "\"args\": " << traceEvent.mArgs;
            }

            outFile << " }";
        }
        outFile.close();
        mTraceEventQueue.clear();
    }
}  // namespace gpgmm
