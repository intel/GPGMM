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

#include "PlatformDebug.h"

#include "Assert.h"
#include "Platform.h"

#include <memory>

#if defined(GPGMM_PLATFORM_WIN32)
#    include <crtdbg.h>
#endif  // defined(GPGMM_PLATFORM_WIN32)

namespace gpgmm {

    class WindowsDebugPlatform : public DebugPlatform {
      public:
        WindowsDebugPlatform() : DebugPlatform() {
            // Explicitly initialize so they are "used" when compiling non-debug builds.
            mStart = {};
            mEnd = {};
            mDiff = {};
        }

        void StartMemoryCheck() override {
            _CrtMemCheckpoint(&mStart);
        }

        bool EndMemoryCheck() override {
            _CrtMemCheckpoint(&mEnd);
            if (_CrtMemDifference(&mDiff, &mStart, &mEnd)) {
                _CrtMemDumpStatistics(&mDiff);
                return true;
            }
            return false;
        }

        void ReportMemoryLeaks() override {
            // Send all reports to STDOUT.
            _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
            _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDOUT);
            _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDOUT);
            // Perform automatic leak checking at program exit through a call to _CrtDumpMemoryLeaks
            // and generate an error report if the application failed to free all the memory it
            // allocated.
#ifdef GPGMM_ENABLE_MEMORY_LEAK_CHECKS
            _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
        }

      private:
        _CrtMemState mStart;
        _CrtMemState mEnd;
        _CrtMemState mDiff;
    };

    DebugPlatform* CreateDebugPlatform() {
#if GPGMM_PLATFORM_WIN32
        return new WindowsDebugPlatform();
#else
        return nullptr;
#endif
    }

}  // namespace gpgmm
