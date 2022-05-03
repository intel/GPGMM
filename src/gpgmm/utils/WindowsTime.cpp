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

#include "Assert.h"
#include "Math.h"
#include "PlatformTime.h"

#include <windows.h>

namespace gpgmm {

    class WindowsTime final : public PlatformTime {
      public:
        WindowsTime() : PlatformTime(), mFrequency(0) {
        }

        double GetAbsoluteTime() override {
            LARGE_INTEGER curTime;
            const bool success = QueryPerformanceCounter(&curTime);
            ASSERT(success);
            return SafeDivison(static_cast<double>(curTime.QuadPart), GetFrequency());
        }

        void StartElapsedTime() override {
            LARGE_INTEGER startCount;
            const bool success = QueryPerformanceCounter(&startCount);
            ASSERT(success);
            mCounterStart = startCount.QuadPart;
        }

        double EndElapsedTime() override {
            LARGE_INTEGER endCount;
            const bool success = QueryPerformanceCounter(&endCount);
            ASSERT(success);
            return SafeDivison(static_cast<double>(endCount.QuadPart - mCounterStart),
                               GetFrequency());
        }

      private:
        LONGLONG GetFrequency() {
            if (mFrequency == 0) {
                LARGE_INTEGER frequency = {};
                QueryPerformanceFrequency(&frequency);

                mFrequency = frequency.QuadPart;
            }

            return mFrequency;
        }

        LONGLONG mFrequency;
        LONGLONG mCounterStart;
    };

    PlatformTime* CreatePlatformTime() {
        return new WindowsTime();
    }

}  // namespace gpgmm
