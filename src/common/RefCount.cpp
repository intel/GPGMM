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

#include "RefCount.h"
#include "Assert.h"

namespace gpgmm {

    RefCounted::RefCounted(int_fast32_t count) : mRef(count) {
    }

    void RefCounted::Ref() {
        mRef.fetch_add(1, std::memory_order_relaxed);
    }

    bool RefCounted::Unref() {
        if (mRef.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            return true;
        }
        return false;
    }

    int_fast32_t RefCounted::RefCount() const {
        return mRef.load(std::memory_order_acquire);
    }

}  // namespace gpgmm
