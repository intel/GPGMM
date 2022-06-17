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

#include "gpgmm/common/StandaloneMemoryAllocator.h"

#include "gpgmm/common/TraceEvent.h"

namespace gpgmm {

    StandaloneMemoryAllocator::StandaloneMemoryAllocator(
        std::unique_ptr<MemoryAllocator> memoryAllocator)
        : MemoryAllocator(std::move(memoryAllocator)) {
    }

    std::unique_ptr<MemoryAllocation> StandaloneMemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "StandaloneMemoryAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        GPGMM_ASSERT_NONZERO(request);

        std::unique_ptr<MemoryAllocation> allocation;
        GPGMM_TRY_ASSIGN(GetNextInChain()->TryAllocateMemory(request), allocation);

        mInfo.UsedBlockCount++;
        mInfo.UsedBlockUsage += request.SizeInBytes;

        return std::make_unique<MemoryAllocation>(
            this, allocation->GetMemory(), /*offset*/ 0, allocation->GetMethod(),
            new MemoryBlock{0, request.SizeInBytes}, request.SizeInBytes);
    }

    void StandaloneMemoryAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "StandaloneMemoryAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        MemoryBlock* block = allocation->GetBlock();
        mInfo.UsedBlockCount--;
        mInfo.UsedBlockUsage -= block->Size;

        SafeDelete(block);
        GetNextInChain()->DeallocateMemory(std::move(allocation));
    }

    MemoryAllocatorInfo StandaloneMemoryAllocator::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        MemoryAllocatorInfo result = mInfo;
        result += GetNextInChain()->GetInfo();
        return result;
    }

    uint64_t StandaloneMemoryAllocator::GetMemoryAlignment() const {
        return GetNextInChain()->GetMemoryAlignment();
    }

    const char* StandaloneMemoryAllocator::GetTypename() const {
        return "StandaloneMemoryAllocator";
    }
}  // namespace gpgmm
