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

#include "gpgmm/common/Assert.h"

namespace gpgmm {
    // Messages with equal or greater to severity will be logged.
    LogSeverity gRecordEventLevel = LogSeverity::Info;

    LogSeverity SetRecordMessageLevel(const LogSeverity& newLevel) {
        LogSeverity oldLevel = gRecordEventLevel;
        gRecordEventLevel = newLevel;
        return oldLevel;
    }

    void RecordMessage(const LogSeverity& severity,
                       const char* name,
                       const std::string& description,
                       int messageId) {
        gpgmm::Log(severity) << name << ": " << description;
#if defined(GPGMM_ENABLE_ASSERT_ON_WARNING)
        ASSERT(severity < LogSeverity::Warning);
#endif
        if (severity >= gRecordEventLevel) {
            LOG_MESSAGE message{description, messageId};
            GPGMM_TRACE_EVENT_OBJECT_CALL(name, message);
        }
    }

}  // namespace gpgmm
