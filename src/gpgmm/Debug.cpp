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

#include "gpgmm/Debug.h"

namespace gpgmm {
    // Messages with equal or greater to severity will be logged.
    LogSeverity gRecordEventLevel = LogSeverity::Info;

    LogSeverity SetRecordLogMessageLevel(const LogSeverity& newLevel) {
        LogSeverity oldLevel = gRecordEventLevel;
        gRecordEventLevel = newLevel;
        return oldLevel;
    }

    void RecordLogMessage(const LogSeverity& severity,
                          const char* name,
                          const std::string& description,
                          int messageId) {
        gpgmm::Log(severity) << name << ": " << description;
        if (severity >= gRecordEventLevel) {
            const LOG_MESSAGE logMessage{description, messageId};
            TRACE_EVENT_INSTANT(name, JSONSerializer::Serialize(logMessage));
        }
    }

}  // namespace gpgmm
