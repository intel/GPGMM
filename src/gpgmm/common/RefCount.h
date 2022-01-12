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

#ifndef GPGMM_COMMON_REFCOUNT_H_
#define GPGMM_COMMON_REFCOUNT_H_

#include <atomic>
#include <cstdint>

namespace gpgmm {

    class RefCounted {
      public:
        RefCounted(int_fast32_t initialRefCount);

        // Increments ref by one.
        void Ref();

        // Decrements ref by one. If count is positive, returns false.
        // Otherwise, returns true when it reaches zero.
        bool Unref();

        // Get the ref count.
        int_fast32_t RefCount() const;

      private:
        mutable std::atomic_int_fast32_t mRef;
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_REFCOUNT_H_
