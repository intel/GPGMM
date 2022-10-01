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

#ifndef TESTS_DUMMYMEMORYALLOCATOR_H_
#define TESTS_DUMMYMEMORYALLOCATOR_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/utils/Utils.h"

namespace gpgmm {

    class DummyMemory : public IMemoryObject, public MemoryBase {
      public:
        DummyMemory(uint64_t size, uint64_t alignment) : MemoryBase(size, alignment) {
        }

        // IMemoryObject
        uint64_t GetSize() const override {
            return MemoryBase::GetSize();
        }

        uint64_t GetAlignment() const override {
            return MemoryBase::GetAlignment();
        }

        void AddSubAllocationRef() override {
            return MemoryBase::AddSubAllocationRef();
        }

        bool RemoveSubAllocationRef() override {
            return MemoryBase::RemoveSubAllocationRef();
        }

        IMemoryPool* GetPool() const override {
            return MemoryBase::GetPool();
        }

        void SetPool(IMemoryPool* pool) override {
            return MemoryBase::SetPool(pool);
        }
    };

    class DummyMemoryAllocator : public MemoryAllocator {
      public:
        DummyMemoryAllocator() = default;

        explicit DummyMemoryAllocator(std::unique_ptr<MemoryAllocator> next)
            : MemoryAllocator(std::move(next)) {
        }

        std::unique_ptr<MemoryAllocation> TryAllocateMemory(
            const MemoryAllocationRequest& request) override {
            TRACE_EVENT0(TraceEventCategory::kDefault, "DummyMemoryAllocator.TryAllocateMemory");

            std::lock_guard<std::mutex> lock(mMutex);

            if (request.NeverAllocate) {
                return {};
            }

            mStats.UsedMemoryCount++;
            mStats.UsedMemoryUsage += request.SizeInBytes;

            return std::make_unique<MemoryAllocation>(
                this, new DummyMemory(request.SizeInBytes, request.Alignment), request.SizeInBytes);
        }

        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override {
            TRACE_EVENT0(TraceEventCategory::kDefault, "DummyMemoryAllocator.DeallocateMemory");

            std::lock_guard<std::mutex> lock(mMutex);

            mStats.UsedMemoryCount--;
            mStats.UsedMemoryUsage -= allocation->GetSize();

            SafeRelease(allocation);
        }
    };

}  // namespace gpgmm

#endif  // TESTS_DUMMYMEMORYALLOCATOR_H_
