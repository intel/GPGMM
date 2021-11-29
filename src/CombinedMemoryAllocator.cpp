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

#include "src/CombinedMemoryAllocator.h"
#include "common/Assert.h"

namespace gpgmm {

    MemoryAllocator* CombinedMemoryAllocator::PushAllocator(
        std::unique_ptr<MemoryAllocator> allocator) {
        mAllocators.push_back(std::move(allocator));
        return mAllocators.back().get();
    }

    std::unique_ptr<MemoryAllocation> CombinedMemoryAllocator::AllocateMemory(uint64_t size,
                                                                              uint64_t alignment,
                                                                              bool neverAllocate) {
        ASSERT(!mAllocators.empty());
        return mAllocators.back()->AllocateMemory(size, alignment, neverAllocate);
    }

    void CombinedMemoryAllocator::DeallocateMemory(MemoryAllocation* allocation) {
        ASSERT(!mAllocators.empty());
        mAllocators.back()->DeallocateMemory(allocation);
    }

    void CombinedMemoryAllocator::ReleaseMemory() {
        for (auto& allocator : mAllocators) {
            ASSERT(allocator != nullptr);
            allocator->ReleaseMemory();
        }
    }

}  // namespace gpgmm
