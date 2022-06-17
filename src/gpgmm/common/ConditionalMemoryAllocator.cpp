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

#include "gpgmm/common/ConditionalMemoryAllocator.h"

#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Assert.h"

namespace gpgmm {

    ConditionalMemoryAllocator::ConditionalMemoryAllocator(
        std::unique_ptr<MemoryAllocator> firstAllocator,
        std::unique_ptr<MemoryAllocator> secondAllocator,
        uint64_t conditionalSize)
        : mFirstAllocator(std::move(firstAllocator)),
          mSecondAllocator(std::move(secondAllocator)),
          mConditionalSize(conditionalSize) {
    }

    std::unique_ptr<MemoryAllocation> ConditionalMemoryAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::Default, "ConditionalMemoryAllocator.TryAllocateMemory");

        if (request.SizeInBytes <= mConditionalSize) {
            return mFirstAllocator->TryAllocateMemory(request);
        } else {
            return mSecondAllocator->TryAllocateMemory(request);
        }
    }

    void ConditionalMemoryAllocator::DeallocateMemory(
        std::unique_ptr<MemoryAllocation> allocation) {
        // ConditionalMemoryAllocator cannot allocate memory itself, so it must not deallocate.
        allocation->GetAllocator()->DeallocateMemory(std::move(allocation));
    }

    MemoryAllocatorInfo ConditionalMemoryAllocator::GetInfo() const {
        MemoryAllocatorInfo result = {};
        result += mFirstAllocator->GetInfo();
        result += mSecondAllocator->GetInfo();
        return result;
    }

    const char* ConditionalMemoryAllocator::GetTypename() const {
        return "ConditionalMemoryAllocator";
    }

    MemoryAllocator* ConditionalMemoryAllocator::GetFirstAllocatorForTesting() const {
        return mFirstAllocator.get();
    }

    MemoryAllocator* ConditionalMemoryAllocator::GetSecondAllocatorForTesting() const {
        return mSecondAllocator.get();
    }

}  // namespace gpgmm
