// Copyright 2019 The Dawn Authors
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

#include "Log.h"

#include "Assert.h"
#include "Platform.h"

#include <cstdio>

#if defined(GPGMM_PLATFORM_ANDROID)
#    include <android/log.h>
#endif

namespace gpgmm {

    // Messages with equal or greater to severity will be logged.
    LogSeverity gLogMessageLevel = LogSeverity::Info;

    namespace {

        const char* SeverityName(LogSeverity severity) {
            switch (severity) {
                case LogSeverity::Debug:
                    return "Debug";
                case LogSeverity::Info:
                    return "Info";
                case LogSeverity::Warning:
                    return "Warning";
                case LogSeverity::Error:
                    return "Error";
                default:
                    UNREACHABLE();
                    return "";
            }
        }

#if defined(GPGMM_PLATFORM_ANDROID)
        android_LogPriority AndroidLogPriority(LogSeverity severity) {
            switch (severity) {
                case LogSeverity::Debug:
                    return ANDROID_LOG_INFO;
                case LogSeverity::Info:
                    return ANDROID_LOG_INFO;
                case LogSeverity::Warning:
                    return ANDROID_LOG_WARN;
                case LogSeverity::Error:
                    return ANDROID_LOG_ERROR;
                default:
                    UNREACHABLE();
                    return ANDROID_LOG_ERROR;
            }
        }
#endif  // defined(GPGMM_PLATFORM_ANDROID)

    }  // anonymous namespace

    // Set the new level and returns the previous level so it may be restored by the caller.
    LogSeverity SetLogMessageLevel(const LogSeverity& newLevel) {
        LogSeverity oldLevel = gLogMessageLevel;
        gLogMessageLevel = newLevel;
        return oldLevel;
    }

    // LogMessage

    LogMessage::LogMessage(LogSeverity severity) : mSeverity(severity) {
    }

    LogMessage::~LogMessage() {
        std::string fullMessage = mStream.str();

        // If this message has been moved, its stream is empty.
        if (fullMessage.empty()) {
            return;
        }

        // If this message is below the global severity level, do not print it.
        if (gLogMessageLevel > mSeverity) {
            return;
        }

        const char* severityName = SeverityName(mSeverity);

        FILE* outputStream = stdout;
        if (mSeverity == LogSeverity::Warning || mSeverity == LogSeverity::Error) {
            outputStream = stderr;
        }

#if defined(GPGMM_PLATFORM_ANDROID)
        android_LogPriority androidPriority = AndroidLogPriority(mSeverity);
        __android_log_print(androidPriority, "Dawn", "%s: %s\n", severityName, fullMessage.c_str());
#else   // defined(GPGMM_PLATFORM_ANDROID)
        // Note: we use fprintf because <iostream> includes static initializers.
        fprintf(outputStream, "%s: %s\n", severityName, fullMessage.c_str());
        fflush(outputStream);
#endif  // defined(GPGMM_PLATFORM_ANDROID)
    }

    LogMessage DebugLog() {
        return {LogSeverity::Debug};
    }

    LogMessage InfoLog() {
        return {LogSeverity::Info};
    }

    LogMessage WarningLog() {
        return {LogSeverity::Warning};
    }

    LogMessage ErrorLog() {
        return {LogSeverity::Error};
    }

    LogMessage DebugLog(const char* file, const char* function, int line) {
        LogMessage message = DebugLog();
        message << file << ":" << line << "(" << function << ")";
        return message;
    }

    LogMessage Log(const LogSeverity& level) {
        switch (level) {
            case LogSeverity::Debug:
                return DebugLog();
            case LogSeverity::Info:
                return InfoLog();
            case LogSeverity::Warning:
                return WarningLog();
            case LogSeverity::Error:
                return ErrorLog();
            default:
                UNREACHABLE();
                return {level};
        }
    }

}  // namespace gpgmm
