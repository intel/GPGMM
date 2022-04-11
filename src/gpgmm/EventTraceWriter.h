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

#ifndef GPGMM_EVENTTRACEWRITER_H_
#define GPGMM_EVENTTRACEWRITER_H_

#include "gpgmm/TraceEvent.h"

#include <mutex>
#include <string>
#include <vector>

namespace gpgmm {

    class PlatformTime;

    class EventTraceWriter {
      public:
        explicit EventTraceWriter(const std::string& traceFile,
                                  bool skipDurationEvents,
                                  bool skipObjectEvents,
                                  bool skipInstantEvents);
        ~EventTraceWriter();

        void EnqueueTraceEvent(char phase,
                               TraceEventCategory category,
                               const char* name,
                               uint64_t id,
                               uint32_t flags,
                               const JSONDict& args);
        void FlushQueuedEventsToDisk();

      private:
        std::vector<TraceEvent> mQueue;
        std::string mTraceFile;
        std::unique_ptr<PlatformTime> mPlatformTime;
        std::mutex mMutex;

        bool mSkipDurationEvents = false;
        bool mSkipObjectEvents = false;
        bool mSkipInstantEvents = false;
    };

}  // namespace gpgmm

#endif  // GPGMM_FILEEVENTTRACE_H_
