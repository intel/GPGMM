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

#ifndef GPGMM_UTILS_PLATFORMTIME_H_
#define GPGMM_UTILS_PLATFORMTIME_H_

namespace gpgmm {

    class PlatformTime {
      public:
        virtual ~PlatformTime() {
        }

        // Return the current time (in seconds) of the platform.
        virtual double GetAbsoluteTime() = 0;

        // Return the elasped time (in seconds) since GetAbsoluteTime() was first called.
        double GetRelativeTime();

        // Used to start a duration or interval of elapsed time (in seconds).
        virtual void StartElapsedTime() = 0;

        // Return the elapsed time (in seconds) since StartElapsedTime() was last called.
        virtual double EndElapsedTime() = 0;
    };

    PlatformTime* CreatePlatformTime();

}  // namespace gpgmm

#endif  // GPGMM_UTILS_PLATFORMTIME_H_
