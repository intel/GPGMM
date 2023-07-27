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

#ifndef SRC_GPGMM_COMMON_MEMORY_H_
#define SRC_GPGMM_COMMON_MEMORY_H_

#include "gpgmm/common/Object.h"
#include "gpgmm/utils/RefCount.h"

namespace gpgmm {

    class MemoryPoolBase;

    // Backend-agnostic device-memory object that can be further sub-allocated.
    // Lifetime is managed by incrementing or decrementing the reference count per allocate or
    // deallocate of the sub-allocations within.
    class MemoryBase : public ObjectBase, public RefCounted {
      public:
        explicit MemoryBase(uint64_t size, uint64_t alignment);
        virtual ~MemoryBase() override;

        uint64_t GetSize() const;
        uint64_t GetAlignment() const;

        MemoryPoolBase* GetPool() const;
        void SetPool(MemoryPoolBase* pool);

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(MemoryBase)

        const uint64_t mSize;
        const uint64_t mAlignment;

        MemoryPoolBase* mPool = nullptr;  // nullptr means no pool is assigned.
    };

}  // namespace gpgmm

#endif  // SRC_GPGMM_COMMON_MEMORY_H_
