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

#include "gpgmm/MemoryAllocator.h"

namespace gpgmm {

    MemoryAllocator::MemoryAllocator(std::unique_ptr<MemoryAllocator> childAllocator) {
        AppendChild(std::move(childAllocator));
    }

    void MemoryAllocator::ReleaseMemory() {
        for (auto alloc = mChildren.head(); alloc != mChildren.end(); alloc = alloc->next()) {
            alloc->value()->ReleaseMemory();
        }
    }

    uint64_t MemoryAllocator::GetMemorySize() const {
        ASSERT(false);
        return kInvalidSize;
    }

    uint64_t MemoryAllocator::GetMemoryAlignment() const {
        ASSERT(false);
        return kInvalidOffset;
    }

    MEMORY_ALLOCATOR_INFO MemoryAllocator::QueryInfo() const {
        if (!HasChild()) {
            return mInfo;
        }

        MEMORY_ALLOCATOR_INFO combinedStats = mInfo;
        for (auto alloc = mChildren.head(); alloc != mChildren.end(); alloc = alloc->next()) {
            const MEMORY_ALLOCATOR_INFO stats = alloc->value()->QueryInfo();
            combinedStats.UsedBlockCount += stats.UsedBlockCount;
            combinedStats.UsedMemoryCount += stats.UsedMemoryCount;
            combinedStats.UsedMemoryUsage += stats.UsedMemoryUsage;
            combinedStats.UsedBlockUsage += stats.UsedBlockUsage;
        }
        return combinedStats;
    }

}  // namespace gpgmm
