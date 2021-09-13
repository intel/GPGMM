// Copyright 2019 The Dawn Authors
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

#ifndef GPGMM_MEMORYALLOCATOR_H_
#define GPGMM_MEMORYALLOCATOR_H_

#include "common/IntegerTypes.h"
#include "src/Allocator.h"
#include "src/MemoryAllocation.h"

namespace gpgmm {
    class MemoryAllocator : public AllocatorBase {
      public:
        virtual ~MemoryAllocator() = default;

        virtual MemoryAllocation SubAllocateMemory(uint64_t size, uint64_t alignment);
        virtual void AllocateMemory(MemoryAllocation** ppAllocation) = 0;
        virtual void DeallocateMemory(MemoryAllocation* pAllocation) = 0;
        virtual void ReleaseMemory();

        virtual uint64_t GetMemorySize() const;
        virtual uint64_t GetMemoryAlignment() const;
        virtual uint64_t GetPoolSizeForTesting() const;

      protected:
        bool IsSubAllocated(const MemoryAllocation& allocation) const;
        void IncrementSubAllocatedRef(MemoryAllocation* pAllocation);
        void DecrementSubAllocatedRef(MemoryAllocation* pAllocation);
    };

}  // namespace gpgmm

#endif  // GPGMM_MEMORYALLOCATOR_H_
