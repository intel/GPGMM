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

#ifndef GPGMM_JSONSERIALIZER_H_
#define GPGMM_JSONSERIALIZER_H_

#include "gpgmm/TraceEvent.h"
#include "gpgmm/common/Log.h"

#include <string>

namespace gpgmm {

    struct POOL_DESC;
    struct ALLOCATOR_MESSAGE;

    class JSONSerializer {
      public:
        static std::string AppendTo(const POOL_DESC& desc);
        static std::string AppendTo(const ALLOCATOR_MESSAGE& desc);
    };

    template <typename T, typename DescT, typename SerializerT = JSONSerializer>
    static void LogObject(const char* name, T* objPtr, const DescT& desc) {
        if (IsEventTracerEnabled()) {
            auto args = SerializerT::AppendTo(desc);
            TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(name, objPtr, args);
        }
    }

    template <typename T, typename SerializerT>
    static void LogEvent(const char* name, const T& obj) {
        if (IsEventTracerEnabled()) {
            auto args = SerializerT::AppendTo(obj);
            TRACE_EVENT_INSTANT(name, args);
        }
    }

    template <typename T, typename SerializerT, typename... Args>
    static void LogEvent(const char* name, const Args&... args) {
        if (IsEventTracerEnabled()) {
            const T& obj{args...};
            return LogEvent<T, SerializerT>(name, obj);
        }
    }

    template <typename T, typename SerializerT = JSONSerializer, typename... Args>
    static void LogMessageEvent(const LogSeverity& severity,
                                const char* name,
                                const Args&... args) {
        const T& obj{args...};
        if (severity >= GetLogLevel()) {
            LogMessage logMessage(severity);
            logMessage << name << SerializerT::AppendTo(obj);
        }

        if (severity >= GetRecordLevel()) {
            return LogEvent<T, SerializerT>(name, obj);
        }
    }
}  // namespace gpgmm

#endif  // GPGMM_JSONSERIALIZER_H_
