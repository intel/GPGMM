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

#include "gpgmm/StandaloneMemoryAllocator.h"

#include "gpgmm/Debug.h"

namespace gpgmm {

    StandaloneMemoryAllocator::StandaloneMemoryAllocator(
        std::unique_ptr<MemoryAllocator> memoryAllocator)
        : MemoryAllocator(std::move(memoryAllocator)) {
    }

    std::unique_ptr<MemoryAllocation> StandaloneMemoryAllocator::TryAllocateMemory(
        uint64_t size,
        uint64_t alignment,
        bool neverAllocate,
        bool cacheSize,
        bool prefetchMemory) {
        TRACE_EVENT0(TraceEventCategory::Default, "StandaloneMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);
        std::unique_ptr<MemoryAllocation> allocation;
        GPGMM_TRY_ASSIGN(GetFirstChild()->TryAllocateMemory(size, alignment, neverAllocate,
                                                            cacheSize, prefetchMemory),
                         allocation);

        mInfo.UsedBlockCount++;
        mInfo.UsedBlockUsage += size;

        return std::make_unique<MemoryAllocation>(this, allocation->GetMemory(), /*offset*/ 0,
                                                  allocation->GetMethod(),
                                                  new MemoryBlock{0, size});
    }

    void StandaloneMemoryAllocator::DeallocateMemory(
        std::unique_ptr<MemoryAllocation> subAllocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "StandaloneMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);
        mInfo.UsedBlockCount--;
        mInfo.UsedBlockUsage -= subAllocation->GetSize();
        SafeDelete(subAllocation->GetBlock());
        GetFirstChild()->DeallocateMemory(std::move(subAllocation));
    }

    MEMORY_ALLOCATOR_INFO StandaloneMemoryAllocator::QueryInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        MEMORY_ALLOCATOR_INFO result = mInfo;
        result += GetFirstChild()->QueryInfo();
        return result;
    }
}  // namespace gpgmm
