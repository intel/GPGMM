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
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm {

    DedicatedMemoryAllocator::DedicatedMemoryAllocator(
        ScopedRef<MemoryAllocatorBase> memoryAllocator,
        uint64_t memoryAlignment)
        : MemoryAllocatorBase(std::move(memoryAllocator)), mMemoryAlignment(memoryAlignment) {
    }

    ResultOrError<std::unique_ptr<MemoryAllocationBase>>
    DedicatedMemoryAllocator::TryAllocateMemory(const MemoryAllocationRequest& request) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "DedicatedMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_RETURN_IF_ERROR(ValidateRequest(request));

        MemoryAllocationRequest memoryRequest = request;
        memoryRequest.Alignment = mMemoryAlignment;
        memoryRequest.SizeInBytes = AlignTo(request.SizeInBytes, mMemoryAlignment);

        std::unique_ptr<MemoryAllocationBase> allocation;
        GPGMM_TRY_ASSIGN(GetNextInChain()->TryAllocateMemory(memoryRequest), allocation);

        mStats.UsedBlockCount++;
        mStats.UsedBlockUsage += allocation->GetSize();

        allocation->SetAllocator(this);

        return allocation;
    }

    void DedicatedMemoryAllocator::DeallocateMemory(
        std::unique_ptr<MemoryAllocationBase> allocation) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "DedicatedMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        mStats.UsedBlockCount--;
        mStats.UsedBlockUsage -= allocation->GetSize();

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
}  // namespace gpgmm
