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

#include "common/Assert.h"
#include "common/IntegerTypes.h"
#include "src/BlockAllocator.h"
#include "src/Memory.h"
#include "src/MemoryAllocation.h"

#include <memory>

namespace gpgmm {

    class MemoryAllocator : public AllocatorBase {
      public:
        virtual ~MemoryAllocator() = default;

        // Combines AllocateBlock and AllocateMemory into a single call.
        // If memory cannot be allocated for the block, the block will also be
        // deallocated instead of allowing it to leak.
        template <typename GetOrCreateMemoryFn>
        MemoryBase* TrySubAllocateMemory(BlockAllocator* blockAllocator,
                                         uint64_t blockSize,
                                         uint64_t blockAlignment,
                                         GetOrCreateMemoryFn&& GetOrCreateMemory) {
            Block* block = blockAllocator->AllocateBlock(blockSize, blockAlignment);
            if (block == nullptr) {
                return nullptr;
            }

            MemoryBase* memory = GetOrCreateMemory(block);
            if (memory == nullptr) {
                blockAllocator->DeallocateBlock(block);
                return nullptr;
            }

            ASSERT(memory != nullptr);
            memory->Ref();

            return memory;
        }

        virtual std::unique_ptr<MemoryAllocation> AllocateMemory(uint64_t size,
                                                                 uint64_t alignment,
                                                                 bool neverAllocate) = 0;
        virtual void DeallocateMemory(MemoryAllocation* allocation) = 0;

        virtual uint64_t GetMemorySize() const;
        virtual uint64_t GetMemoryAlignment() const;
    };

}  // namespace gpgmm

#endif  // GPGMM_MEMORYALLOCATOR_H_
