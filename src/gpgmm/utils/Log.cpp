// Copyright 2019 The Dawn Authors
// Copyright 2022 The GPGMM Authors
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
#include <mutex>
#include <thread>

#if defined(GPGMM_PLATFORM_ANDROID)
#    include <android/log.h>
#elif defined(GPGMM_PLATFORM_WINDOWS)
#    include <windows.h>
#endif  // defined(GPGMM_PLATFORM_WINDOWS)

namespace gpgmm {

    static const char kLogTag[] = "GPGMM";

    MessageSeverity GetDefaultLogLevel() {
#if defined(NDEBUG)
        return MessageSeverity::Info;
#else
        return MessageSeverity::Debug;
#endif  // defined(NDEBUG)
    }

    // Messages with equal or greater to severity will be logged.
    static MessageSeverity gLogLevel = GetDefaultLogLevel();
    static std::mutex mMutex;

    namespace {

        const char* SeverityName(MessageSeverity severity) {
            switch (severity) {
                case MessageSeverity::Debug:
                    return "Debug";
                case MessageSeverity::Info:
                    return "Info";
                case MessageSeverity::Warning:
                    return "Warning";
                case MessageSeverity::Error:
                    return "Error";
                default:
                    UNREACHABLE();
                    return "";
            }
        }

#if defined(GPGMM_PLATFORM_ANDROID)
        android_LogPriority AndroidLogPriority(MessageSeverity severity) {
            switch (severity) {
                case MessageSeverity::Debug:
                    return ANDROID_LOG_INFO;
                case MessageSeverity::Info:
                    return ANDROID_LOG_INFO;
                case MessageSeverity::Warning:
                    return ANDROID_LOG_WARN;
                case MessageSeverity::Error:
                    return ANDROID_LOG_ERROR;
                default:
                    UNREACHABLE();
                    return ANDROID_LOG_ERROR;
            }
        }
#endif  // defined(GPGMM_PLATFORM_ANDROID)

    }  // anonymous namespace

    void SetLogLevel(const MessageSeverity& newLevel) {
        std::lock_guard<std::mutex> lock(mMutex);
        gLogLevel = newLevel;
    }

    MessageSeverity GetLogLevel() {
        std::lock_guard<std::mutex> lock(mMutex);
        return gLogLevel;
    }

    // LogMessage

    LogMessage::LogMessage(MessageSeverity severity) : mSeverity(severity) {
    }

    LogMessage::~LogMessage() {
        std::string fullMessage = mStream.str();

        // If this message has been moved, its stream is empty.
        if (fullMessage.empty()) {
            return;
        }

        const char* severityName = SeverityName(mSeverity);

        FILE* outputStream = stdout;
        if (mSeverity == MessageSeverity::Warning || mSeverity == MessageSeverity::Error) {
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
        if (GetLogLevel() > mSeverity) {
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
        return {MessageSeverity::Debug};
    }

    LogMessage InfoLog() {
        return {MessageSeverity::Info};
    }

    LogMessage WarningLog() {
        return {MessageSeverity::Warning};
    }

    LogMessage ErrorLog() {
        return {MessageSeverity::Error};
    }

    LogMessage DebugLog(const char* file, const char* function, int line) {
        LogMessage message = DebugLog();
        message << file << ":" << line << "(" << function << ")";
        return message;
    }

    LogMessage Log(const MessageSeverity& level) {
        switch (level) {
            case MessageSeverity::Debug:
                return DebugLog();
            case MessageSeverity::Info:
                return InfoLog();
            case MessageSeverity::Warning:
                return WarningLog();
            case MessageSeverity::Error:
                return ErrorLog();
            default:
                UNREACHABLE();
                return {level};
        }
    }

}  // namespace gpgmm
