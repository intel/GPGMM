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

#ifndef GPGMM_COMMON_EVENTTRACEWRITER_H_
#define GPGMM_COMMON_EVENTTRACEWRITER_H_

#include "gpgmm/common/TraceEvent.h"

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace gpgmm {

    class PlatformTime;
    class ScopedTraceBufferInTLS;

    class EventTraceWriter {
      public:
        EventTraceWriter();
        ~EventTraceWriter();

        void SetConfiguration(const std::string& traceFile, const TraceEventPhase& ignoreMask);

        void EnqueueTraceEvent(std::shared_ptr<EventTraceWriter> writer,
                               char phase,
                               TraceEventCategory category,
                               const char* name,
                               uint64_t id,
                               uint32_t flags,
                               const JSONDict& args);

        void FlushQueuedEventsToDisk();

        void FlushAndRemoveBufferEntry(std::vector<TraceEvent>* buffer);

        size_t GetQueuedEventsForTesting() const;

      private:
        ScopedTraceBufferInTLS* GetOrCreateBufferFromTLS(std::shared_ptr<EventTraceWriter> writer);
        std::vector<TraceEvent> MergeAndClearBuffers();

        std::string mTraceFile;
        TraceEventPhase mIgnoreMask;

        std::unique_ptr<PlatformTime> mPlatformTime;

        mutable std::mutex mMutex;

        std::unordered_map<std::thread::id, ScopedTraceBufferInTLS*> mBufferPerThread;
        std::vector<TraceEvent> mUnmergedBuffer;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_EVENTTRACEWRITER_H_
