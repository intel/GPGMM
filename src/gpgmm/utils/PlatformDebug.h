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

#ifndef GPGMM_UTILS_PLATFORMDEBUG_H_
#define GPGMM_UTILS_PLATFORMDEBUG_H_

namespace gpgmm {

    class DebugPlatform {
      public:
        // Starts memory leak checking, if supported.
        virtual void StartMemoryCheck() {
        }

        // End memory leak checking and return true if a memory leak was detected.
        virtual bool EndMemoryCheck() {
            return false;
        }

        // Output or dump leak detection to console.
        virtual void ReportMemoryLeaks() {
        }

        virtual ~DebugPlatform() = default;
    };

    DebugPlatform* CreateDebugPlatform();

}  // namespace gpgmm

#endif  // GPGMM_UTILS_PLATFORMDEBUG_H_
