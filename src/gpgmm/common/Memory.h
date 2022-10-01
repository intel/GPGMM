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

#ifndef GPGMM_COMMON_MEMORY_H_
#define GPGMM_COMMON_MEMORY_H_

#include "gpgmm/common/Object.h"
#include "gpgmm/utils/RefCount.h"

#include <gpgmm.h>

namespace gpgmm {

    class MemoryBase : public ObjectBase {
      public:
        explicit MemoryBase(uint64_t size, uint64_t alignment);
        virtual ~MemoryBase() override;

        uint64_t GetSize() const;
        uint64_t GetAlignment() const;

        IMemoryPool* GetPool() const;
        void SetPool(IMemoryPool* pool);

        void AddSubAllocationRef();
        bool RemoveSubAllocationRef();

      private:
        const char* GetTypename() const override;

        RefCounted mSubAllocationRefs;

        const uint64_t mSize;
        const uint64_t mAlignment;

        IMemoryPool* mPool = nullptr;  // nullptr means no pool is assigned.
    };

}  // namespace gpgmm

#endif  // GPGMM_COMMON_MEMORY_H_
