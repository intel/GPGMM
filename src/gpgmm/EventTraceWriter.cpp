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

#include "gpgmm/EventTraceWriter.h"

#include "gpgmm/common/Assert.h"
#include "gpgmm/common/PlatformTime.h"
#include "gpgmm/common/PlatformUtils.h"
#include "gpgmm/common/Utils.h"

#include <fstream>
#include <sstream>
#include <string>
#include <thread>

namespace gpgmm {

    EventTraceWriter::EventTraceWriter(const std::string& traceFile,
                                       bool skipDurationEvents,
                                       bool skipObjectEvents,
                                       bool skipInstantEvents)
        : mTraceFile(traceFile),
          mPlatformTime(CreatePlatformTime()),
          mSkipDurationEvents(skipDurationEvents),
          mSkipObjectEvents(skipObjectEvents),
          mSkipInstantEvents(skipInstantEvents) {
        ASSERT(!mTraceFile.empty());
    }

    EventTraceWriter::~EventTraceWriter() {
        FlushQueuedEventsToDisk();
    }

    void EventTraceWriter::EnqueueTraceEvent(char phase,
                                             TraceEventCategory category,
                                             const char* name,
                                             uint64_t id,
                                             uint32_t flags,
                                             const JSONDict& args) {
        std::unique_lock<std::mutex> lock(mMutex);
        const double timestampInSeconds = mPlatformTime->GetRelativeTime();
        const uint32_t threadID = std::stoi(ToString(std::this_thread::get_id()));
        if (timestampInSeconds != 0) {
            mQueue.push_back(
                {phase, category, name, id, threadID, timestampInSeconds, flags, args});
        }
    }

    void EventTraceWriter::FlushQueuedEventsToDisk() {
        std::unique_lock<std::mutex> lock(mMutex);

        JSONArray traceEvents;
        for (const TraceEvent& traceEvent : mQueue) {
            if (mSkipDurationEvents && (traceEvent.mPhase == TRACE_EVENT_PHASE_BEGIN ||
                                        traceEvent.mPhase == TRACE_EVENT_PHASE_END)) {
                continue;
            }

            if (mSkipObjectEvents && (traceEvent.mPhase == TRACE_EVENT_PHASE_CREATE_OBJECT ||
                                      traceEvent.mPhase == TRACE_EVENT_PHASE_DELETE_OBJECT ||
                                      traceEvent.mPhase == TRACE_EVENT_PHASE_SNAPSHOT_OBJECT)) {
                continue;
            }

            if (mSkipInstantEvents && (traceEvent.mPhase == TRACE_EVENT_PHASE_INSTANT)) {
                continue;
            }

            JSONDict eventData;
            eventData.AddItem("name", traceEvent.mName);

            switch (traceEvent.mCategory) {
                case TraceEventCategory::Default:
                    eventData.AddItem("cat", "default");
                    break;

                case TraceEventCategory::Metadata:
                    eventData.AddItem("cat", "__metadata");
                    break;

                default:
                    UNREACHABLE();
                    break;
            }

            eventData.AddItem("ph", traceEvent.mPhase);

            const uint32_t idFlags =
                traceEvent.mFlags & (TRACE_EVENT_FLAG_HAS_ID | TRACE_EVENT_FLAG_HAS_LOCAL_ID |
                                     TRACE_EVENT_FLAG_HAS_GLOBAL_ID);

            if (idFlags) {
                std::stringstream traceEventID;
                traceEventID << std::hex << traceEvent.mID;

                switch (idFlags) {
                    case TRACE_EVENT_FLAG_HAS_ID:
                        eventData.AddItem("id", "0x" + traceEventID.str());
                        break;

                    case TRACE_EVENT_FLAG_HAS_LOCAL_ID: {
                        JSONDict localID;
                        localID.AddItem("local", "0x" + traceEventID.str());
                        eventData.AddItem("id2", localID);
                        break;
                    }

                    case TRACE_EVENT_FLAG_HAS_GLOBAL_ID: {
                        JSONDict globalID;
                        globalID.AddItem("global", "0x" + traceEventID.str());
                        eventData.AddItem("id2", globalID);
                        break;
                    }

                    default:
                        UNREACHABLE();
                        break;
                }
            }

            eventData.AddItem("tid", traceEvent.mTID);

            const uint64_t microseconds =
                static_cast<uint64_t>(traceEvent.mTimestamp * 1000.0 * 1000.0);
            eventData.AddItem("ts", microseconds);
            eventData.AddItem("pid", GetPID());

            if (!traceEvent.mArgs.IsEmpty()) {
                eventData.AddItem("args", traceEvent.mArgs);
            }

            traceEvents.AddItem(eventData);
        }

        JSONDict traceData;
        traceData.AddItem("traceEvents", traceEvents);

        std::ofstream outFile;
        outFile.open(mTraceFile);
        outFile << traceData.ToString();
        outFile.flush();
        outFile.close();
        mQueue.clear();
    }

}  // namespace gpgmm
