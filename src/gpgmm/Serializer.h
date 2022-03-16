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

#ifndef GPGMM_SERIALIZER_H_
#define GPGMM_SERIALIZER_H_

#include "gpgmm/TraceEvent.h"
#include "gpgmm/common/Log.h"

#include <string>

namespace gpgmm {

    // Messages of a given severity to be recorded.
    // Set the new level and returns the previous level so it may be restored by the caller.
    LogSeverity SetRecordLogMessageLevel(const LogSeverity& level);

    // Forward declare common types.
    struct POOL_INFO;
    struct MEMORY_ALLOCATOR_INFO;

    struct LOG_MESSAGE {
        std::string Description;
        int ID;
    };

    class Serializer {
      public:
        static JSONDict Serialize(const LOG_MESSAGE& desc);
        static JSONDict Serialize(const MEMORY_ALLOCATOR_INFO& info);
        static JSONDict Serialize(const POOL_INFO& desc);
        static JSONDict Serialize(void* objectPtr);
    };

    template <typename T, typename DescT, typename SerializerT = Serializer>
    static void RecordObject(const char* name, T* objPtr, const DescT& desc) {
        if (IsEventTracerEnabled()) {
            TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(name, objPtr, SerializerT::Serialize(desc));
        }
    }

    template <typename T, typename SerializerT, typename... Args>
    static void RecordCall(const char* name, const Args&... args) {
        if (IsEventTracerEnabled()) {
            const T& obj{args...};
            TRACE_EVENT_INSTANT(name, SerializerT::Serialize(obj));
        }
    }

    void RecordLogMessage(const LogSeverity& severity,
                          const char* name,
                          const std::string& description,
                          int messageId);

}  // namespace gpgmm

#endif  // GPGMM_SERIALIZER_H_
