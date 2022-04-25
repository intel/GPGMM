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

#ifndef GPGMM_BLOCKALLOCATOR_H_
#define GPGMM_BLOCKALLOCATOR_H_

#include "gpgmm/Allocator.h"
#include "gpgmm/common/Limits.h"

namespace gpgmm {

    struct MemoryBlock {
        uint64_t Offset = kInvalidOffset;
        uint64_t Size = kInvalidSize;
    };

    // Allocates a sub-range [offset, offset + size) in usually a byte-addressable range.
    class BlockAllocator : public AllocatorBase {
      public:
        virtual ~BlockAllocator() = default;

        virtual MemoryBlock* TryAllocateBlock(uint64_t requestSize, uint64_t alignment) = 0;
        virtual void DeallocateBlock(MemoryBlock* block) = 0;
    };

}  // namespace gpgmm

#endif  // GPGMM_BLOCKALLOCATOR_H_
