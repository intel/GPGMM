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

#include <sstream>
#include <string>

namespace gpgmm {

    // Messages of a given severity to be recorded.
    void SetRecordEventLevel(const LogSeverity& level);
    const LogSeverity& GetRecordEventLevel();

    class JSONDict {
      public:
        JSONDict();

        std::string ToString() const;

        // Per JSON data type
        void AddItem(const std::string& name, std::string value);
        void AddItem(const std::string& name, uint64_t value);
        void AddItem(const std::string& name, uint32_t value);
        void AddItem(const std::string& name, bool value);
        void AddItem(const std::string& name, float value);
        void AddItem(const std::string& name, int value);
        void AddItem(const std::string& name, unsigned char value);
        void AddItem(const std::string& name, const JSONDict& object);

      private:
        void AddString(const std::string& name, const std::string& value);

        bool mHasItem = false;
        std::stringstream mSS;
    };

    // Forward declare common types.
    struct ALLOCATOR_MESSAGE;
    struct POOL_DESC;
    struct MEMORY_ALLOCATOR_INFO;

    class JSONSerializer {
      public:
        static JSONDict Serialize(const ALLOCATOR_MESSAGE& desc);
        static JSONDict Serialize(const MEMORY_ALLOCATOR_INFO& info);
        static JSONDict Serialize(const POOL_DESC& desc);
        static JSONDict Serialize(void* ptr);
    };

    template <typename T, typename DescT, typename SerializerT = JSONSerializer>
    static void LogEvent(const char* name, T* objPtr, const DescT& desc) {
        if (IsEventTracerEnabled()) {
            auto args = SerializerT::Serialize(desc).ToString();
            TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(name, objPtr, args);
        }
    }

    template <typename T, typename SerializerT>
    static void LogEvent(const char* name, const T& obj) {
        if (IsEventTracerEnabled()) {
            auto args = SerializerT::Serialize(obj).ToString();
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

    template <typename T, typename SerializerT, typename... Args>
    static void LogCommon(const LogSeverity& severity, const char* name, const Args&... args) {
        const T& obj{args...};
        gpgmm::Log(severity) << name << SerializerT::Serialize(obj).ToString();
        if (severity >= GetRecordEventLevel()) {
            return LogEvent<T, SerializerT>(name, obj);
        }
    }

    template <typename... Args>
    static void LogAllocatorMessage(const LogSeverity& severity,
                                    const char* name,
                                    const Args&... args) {
        return gpgmm::LogCommon<ALLOCATOR_MESSAGE, JSONSerializer>(severity, name, args...);
    }

}  // namespace gpgmm

#endif  // GPGMM_JSONSERIALIZER_H_
