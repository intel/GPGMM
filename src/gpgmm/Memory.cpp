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

#include "gpgmm/Memory.h"

#include "gpgmm/MemoryPool.h"
#include "gpgmm/utils/Assert.h"

namespace gpgmm {

    MemoryBase::MemoryBase(uint64_t size) : RefCounted(0), mSize(size) {
        ASSERT(mSize != kInvalidSize);
    }

    MemoryBase::~MemoryBase() {
        ASSERT(GetRefCount() == 0);
    }

    uint64_t MemoryBase::GetSize() const {
        return mSize;
    }

    MemoryPool* MemoryBase::GetPool() const {
        return mPool;
    }

    void MemoryBase::SetPool(MemoryPool* pool) {
        ASSERT(pool != nullptr);
        mPool = pool;
    }

}  // namespace gpgmm
