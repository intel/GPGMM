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

#include "gpgmm/common/MemoryPool.h"

#include "gpgmm/common/TraceEvent.h"

namespace gpgmm {

    MemoryPoolBase::MemoryPoolBase(uint64_t memorySize) : mMemorySize(memorySize) {
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);
    }

    MemoryPoolBase::~MemoryPoolBase() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
    }

    std::unique_ptr<MemoryAllocationBase> MemoryPoolBase::AcquireFromPoolForTesting(
        uint64_t indexInPool) {
        return AcquireFromPool(indexInPool).AcquireResult();
    }

    uint64_t MemoryPoolBase::GetMemorySize() const {
        return mMemorySize;
    }

}  // namespace gpgmm
