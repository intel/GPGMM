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
        return MessageSeverity::kInfo;
#else
        return MessageSeverity::kDebug;
#endif  // defined(NDEBUG)
    }

    // Messages with equal or greater to severity will be logged.
    static MessageSeverity gLogLevel = GetDefaultLogLevel();
    static std::mutex mMutex;

    namespace {

        const char* SeverityName(MessageSeverity severity) {
            switch (severity) {
                case MessageSeverity::kDebug:
                    return "Debug";
                case MessageSeverity::kInfo:
                    return "Info";
                case MessageSeverity::kWarning:
                    return "Warning";
                case MessageSeverity::kError:
                    return "Error";
                default:
                    UNREACHABLE();
                    return "";
            }
        }

#if defined(GPGMM_PLATFORM_ANDROID)
        android_LogPriority AndroidLogPriority(MessageSeverity severity) {
            switch (severity) {
                case MessageSeverity::kDebug:
                    return ANDROID_LOG_INFO;
                case MessageSeverity::kInfo:
                    return ANDROID_LOG_INFO;
                case MessageSeverity::kWarning:
                    return ANDROID_LOG_WARN;
                case MessageSeverity::kError:
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

    LogMessage::LogMessage(MessageSeverity severity, MessageId messageId) noexcept
        : mSeverity(severity), mMessageId(messageId) {
    }

    LogMessage::~LogMessage() {
        std::string fullMessage = mStream.str();

        // If this message has been moved, its stream is empty.
        if (fullMessage.empty()) {
            return;
        }

        const char* severityName = SeverityName(mSeverity);

        FILE* outputStream = stdout;
        if (mSeverity == MessageSeverity::kWarning || mSeverity == MessageSeverity::kError) {
            outputStream = stderr;
        }

        // Displays a message to the debug console with the error message in it.
        // This is for development only; we don't use this in circumstances (like release builds)
        // where users could see it, since users don't understand these messages anyway.
#if defined(GPGMM_PLATFORM_WINDOWS)
        if (IsDebuggerPresent()) {
            std::string outputString;
            if (mMessageId != MessageId::kUnknown) {
                outputString = std::string(kLogTag) + " " + std::string(severityName) +
                               "(tid: " + ToString(std::this_thread::get_id()) +
                               "): " + fullMessage + "[" + GetMessageFromID(mMessageId) + "]" +
                               "\n";
            } else {
                outputString = std::string(kLogTag) + " " + std::string(severityName) +
                               "(tid: " + ToString(std::this_thread::get_id()) +
                               "): " + fullMessage + "\n";
            }

            OutputDebugStringA(outputString.c_str());
        }
#endif  // defined(GPGMM_PLATFORM_WINDOWS)

        // If this message is below the global severity level, do not print it.
        if (GetLogLevel() > mSeverity) {
            return;
        }

        // Do not dump anything below info level messages to STDOUT.
        if (mSeverity < MessageSeverity::kInfo) {
            return;
        }

#if defined(GPGMM_PLATFORM_ANDROID)
        android_LogPriority androidPriority = AndroidLogPriority(mSeverity);
        __android_log_print(androidPriority, "GPGMM", "%s: %s\n", severityName,
                            fullMessage.c_str());
#else  // defined(GPGMM_PLATFORM_ANDROID)
       // Note: we use fprintf because <iostream> includes static initializers.
        if (mMessageId != MessageId::kUnknown) {
            fprintf(outputStream, "%s %s (tid:%s): %s [%s]\n", kLogTag, severityName,
                    ToString(std::this_thread::get_id()).c_str(), fullMessage.c_str(),
                    GetMessageFromID(mMessageId));
        } else {
            fprintf(outputStream, "%s %s (tid:%s): %s\n", kLogTag, severityName,
                    ToString(std::this_thread::get_id()).c_str(), fullMessage.c_str());
        }
        fflush(outputStream);
#endif
    }

    LogMessage DebugLog(MessageId messageId) {
        return {MessageSeverity::kDebug, messageId};
    }

    LogMessage InfoLog(MessageId messageId) {
        return {MessageSeverity::kInfo, messageId};
    }

    LogMessage WarningLog(MessageId messageId) {
        return {MessageSeverity::kWarning, messageId};
    }

    LogMessage ErrorLog(MessageId messageId) {
        return {MessageSeverity::kError, messageId};
    }

    LogMessage DebugLog(const char* file, const char* function, int line) {
        LogMessage message = DebugLog();
        message << file << ":" << line << "(" << function << ")";
        return message;
    }

    LogMessage Log(MessageSeverity severity, MessageId messageId) {
        switch (severity) {
            case MessageSeverity::kDebug:
                return DebugLog(messageId);
            case MessageSeverity::kInfo:
                return InfoLog(messageId);
            case MessageSeverity::kWarning:
                return WarningLog(messageId);
            case MessageSeverity::kError:
                return ErrorLog(messageId);
            default:
                UNREACHABLE();
                return {severity, messageId};
        }
    }

}  // namespace gpgmm
