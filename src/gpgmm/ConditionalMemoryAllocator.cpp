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

#include "gpgmm/ConditionalMemoryAllocator.h"
#include "gpgmm/common/Assert.h"

namespace gpgmm {

    ConditionalMemoryAllocator::ConditionalMemoryAllocator(
        std::unique_ptr<MemoryAllocator> firstAllocator,
        std::unique_ptr<MemoryAllocator> secondAllocator,
        uint64_t conditionalSize)
        : mFirstAllocator(AppendChild(std::move(firstAllocator))),
          mSecondAllocator(AppendChild(std::move(secondAllocator))),
          mConditionalSize(conditionalSize) {
    }

    std::unique_ptr<MemoryAllocation> ConditionalMemoryAllocator::TryAllocateMemory(
        uint64_t allocationSize,
        uint64_t alignment,
        bool neverAllocate,
        bool cacheSize) {
        if (allocationSize <= mConditionalSize) {
            return mFirstAllocator->TryAllocateMemory(allocationSize, alignment, neverAllocate,
                                                      cacheSize);
        } else {
            return mSecondAllocator->TryAllocateMemory(allocationSize, alignment, neverAllocate,
                                                       cacheSize);
        }
    }

    void ConditionalMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        // ConditionalMemoryAllocator cannot allocate memory itself, so it must not deallocate.
        allocation->GetAllocator()->DeallocateMemory(allocation);
    }

    MemoryAllocator* ConditionalMemoryAllocator::GetFirstAllocatorForTesting() const {
        return mFirstAllocator;
    }

    MemoryAllocator* ConditionalMemoryAllocator::GetSecondAllocatorForTesting() const {
        return mSecondAllocator;
    }

}  // namespace gpgmm
