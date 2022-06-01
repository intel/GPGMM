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

#ifndef TESTS_DUMMYMEMORYALLOCATOR_H_
#define TESTS_DUMMYMEMORYALLOCATOR_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Utils.h"

namespace gpgmm {

    class DummyMemoryAllocator : public MemoryAllocator {
      public:
        DummyMemoryAllocator() = default;

        explicit DummyMemoryAllocator(std::unique_ptr<MemoryAllocator> next)
            : MemoryAllocator(std::move(next)) {
        }

        std::unique_ptr<MemoryAllocation> TryAllocateMemory(
            const MEMORY_ALLOCATION_REQUEST& request) override {
            TRACE_EVENT0(TraceEventCategory::Default, "DummyMemoryAllocator.TryAllocateMemory");

            std::lock_guard<std::mutex> lock(mMutex);

            if (request.NeverAllocate) {
                return {};
            }

            mInfo.UsedMemoryCount++;
            mInfo.UsedMemoryUsage += request.SizeInBytes;
            return std::make_unique<MemoryAllocation>(
                this, new MemoryBase(request.SizeInBytes, request.Alignment));
        }

        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override {
            TRACE_EVENT0(TraceEventCategory::Default, "DummyMemoryAllocator.DeallocateMemory");

            std::lock_guard<std::mutex> lock(mMutex);

            mInfo.UsedMemoryCount--;
            mInfo.UsedMemoryUsage -= allocation->GetSize();
            SafeRelease(allocation);
        }
    };

}  // namespace gpgmm

#endif  // TESTS_DUMMYMEMORYALLOCATOR_H_
