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

#include "gpgmm/common/MemoryPool.h"

#include "gpgmm/common/Debug.h"

namespace gpgmm {

    MemoryPool::MemoryPool(uint64_t memorySize) : mMemorySize(memorySize) {
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);
    }

    MemoryPool::~MemoryPool() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
    }

    uint64_t MemoryPool::GetMemorySize() const {
        return mMemorySize;
    }

    POOL_INFO MemoryPool::GetInfo() const {
        return {GetPoolSize() * mMemorySize};
    }

    const char* MemoryPool::GetTypename() const {
        return "MemoryPool";
    }

}  // namespace gpgmm
