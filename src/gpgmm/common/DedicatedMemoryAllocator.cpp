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

#include "gpgmm/common/DedicatedMemoryAllocator.h"

#include "gpgmm/common/MemoryBlock.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm {

    DedicatedMemoryAllocator::DedicatedMemoryAllocator(
        std::unique_ptr<MemoryAllocator> memoryAllocator,
        uint64_t memoryAlignment)
        : MemoryAllocator(std::move(memoryAllocator)), mMemoryAlignment(memoryAlignment) {
    }

    ResultOrError<std::unique_ptr<MemoryAllocation>> DedicatedMemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "DedicatedMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_INVALID_IF(!ValidateRequest(request));

        MemoryAllocationRequest memoryRequest = request;
        memoryRequest.Alignment = mMemoryAlignment;

        std::unique_ptr<MemoryAllocation> allocation;
        GPGMM_TRY_ASSIGN(GetNextInChain()->TryAllocateMemory(memoryRequest), allocation);

        mStats.UsedBlockCount++;
        mStats.UsedBlockUsage += allocation->GetSize();

        return std::make_unique<MemoryAllocation>(
            this, allocation->GetMemory(), /*offset*/ 0, allocation->GetMethod(),
            new MemoryBlock{0, allocation->GetSize()}, request.SizeInBytes);
    }

    void DedicatedMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "DedicatedMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        MemoryBlock* block = allocation->GetBlock();
        mStats.UsedBlockCount--;
        mStats.UsedBlockUsage -= block->Size;

        SafeDelete(block);
        GetNextInChain()->DeallocateMemory(std::move(allocation));
    }

    MemoryAllocatorStats DedicatedMemoryAllocator::GetStats() const {
        std::lock_guard<std::mutex> lock(mMutex);
        MemoryAllocatorStats result = mStats;
        result += GetNextInChain()->GetStats();
        return result;
    }

    uint64_t DedicatedMemoryAllocator::GetMemoryAlignment() const {
        return mMemoryAlignment;
    }

    const char* DedicatedMemoryAllocator::GetTypename() const {
        return "DedicatedMemoryAllocator";
    }
}  // namespace gpgmm
