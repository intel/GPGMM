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
#include "Utils.h"

#include <cstdio>
#include <thread>

#if defined(GPGMM_PLATFORM_ANDROID)
#    include <android/log.h>
#elif defined(GPGMM_PLATFORM_WINDOWS)
#    include <windows.h>
#endif  // defined(GPGMM_PLATFORM_WINDOWS)

namespace gpgmm {

    static const char kLogTag[] = "GPGMM";

    LogSeverity GetDefaultLogMessageLevel() {
#if defined(NDEBUG)
        return LogSeverity::Info;
#else
        return LogSeverity::Debug;
#endif  // defined(NDEBUG)
    }

    // Messages with equal or greater to severity will be logged.
    static LogSeverity gLogMessageLevel = GetDefaultLogMessageLevel();

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

    void SetLogMessageLevel(const LogSeverity& newLevel) {
        gLogMessageLevel = newLevel;
    }

    const LogSeverity& GetLogMessageLevel() {
        return gLogMessageLevel;
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

        const char* severityName = SeverityName(mSeverity);

        FILE* outputStream = stdout;
        if (mSeverity == LogSeverity::Warning || mSeverity == LogSeverity::Error) {
            outputStream = stderr;
        }

        // Displays a message to the debug console with the error message in it.
        // This is for development only; we don't use this in circumstances (like release builds)
        // where users could see it, since users don't understand these messages anyway.
#if defined(GPGMM_PLATFORM_WINDOWS)
        if (IsDebuggerPresent()) {
            const std::string outputString =
                std::string(kLogTag) + " " + std::string(severityName) +
                "(tid: " + ToString(std::this_thread::get_id()) + "): " + fullMessage + "\n";
            OutputDebugStringA(outputString.c_str());
        }
#endif  // defined(GPGMM_PLATFORM_WINDOWS)

        // If this message is below the global severity level, do not print it.
        if (gLogMessageLevel > mSeverity) {
            return;
        }

#if defined(GPGMM_PLATFORM_ANDROID)
        android_LogPriority androidPriority = AndroidLogPriority(mSeverity);
        __android_log_print(androidPriority, "GPGMM", "%s: %s\n", severityName,
                            fullMessage.c_str());
#else  // defined(GPGMM_PLATFORM_ANDROID)
       // Note: we use fprintf because <iostream> includes static initializers.
        fprintf(outputStream, "%s %s (tid:%s): %s\n", kLogTag, severityName,
                ToString(std::this_thread::get_id()).c_str(), fullMessage.c_str());
        fflush(outputStream);
#endif
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
