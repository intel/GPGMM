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

#include "gpgmm/MemoryPool.h"

#include "gpgmm/TraceEvent.h"

namespace gpgmm {

    MemoryPool::MemoryPool() {
        TRACE_EVENT_OBJECT_CREATED_WITH_ID("GPUMemoryPool", this);
    }

    MemoryPool::~MemoryPool() {
        TRACE_EVENT_OBJECT_DELETED_WITH_ID("GPUMemoryPool", this);
    }

    POOL_DESC MemoryPool::GetDesc() const {
        return {GetPoolSize()};
    }

}  // namespace gpgmm
