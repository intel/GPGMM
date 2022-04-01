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

#ifndef GPGMM_DEBUG_H_
#define GPGMM_DEBUG_H_

#include "gpgmm/JSONSerializer.h"
#include "gpgmm/TraceEvent.h"
#include "gpgmm/common/Log.h"

#include <string>

namespace gpgmm {

    struct LOG_MESSAGE {
        std::string Description;
        int ID;
    };

    // Messages of a given severity to be recorded.
    // Set the new level and returns the previous level so it may be restored by the caller.
    LogSeverity SetRecordMessageLevel(const LogSeverity& level);

    void RecordMessage(const LogSeverity& severity,
                       const char* name,
                       const std::string& description,
                       int messageId);

// Helper macro to avoid evaluating the arguments when the condition doesn't hold.
#define GPGMM_LAZY_SERIALIZE(object, condition) \
    !(condition) ? gpgmm::JSONSerializer::Serialize() : SerializerT::Serialize(object)

    template <typename T, typename DescT, typename SerializerT = JSONSerializer>
    static void RecordObject(const char* name, T* objPtr, const DescT& desc) {
        TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(TraceEventCategory::Default, name, objPtr,
                                            GPGMM_LAZY_SERIALIZE(desc, IsEventTracerEnabled()));
    }

    template <typename T, typename SerializerT, typename... Args>
    static void RecordCall(const char* name, const Args&... args) {
        TRACE_EVENT_INSTANT(TraceEventCategory::Default, name,
                            GPGMM_LAZY_SERIALIZE(T{args...}, IsEventTracerEnabled()));
    }

}  // namespace gpgmm

#endif  // GPGMM_DEBUG_H_
