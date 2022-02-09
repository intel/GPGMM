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

#ifndef GPGMM_COMMON_NONCOPYABLE_H_
#define GPGMM_COMMON_NONCOPYABLE_H_

namespace gpgmm {

    class NonCopyable {
      protected:
        NonCopyable() = default;
        ~NonCopyable() = default;

        // Movable constructor and assignment.
        NonCopyable(NonCopyable&&) = default;
        NonCopyable& operator=(NonCopyable&&) = default;

      private:
        // Not copyable constructor and assignment.
        NonCopyable(const NonCopyable&) = delete;
        NonCopyable& operator=(const NonCopyable&) = delete;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_NONCOPYABLE_H_
