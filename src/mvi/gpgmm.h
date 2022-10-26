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

#ifndef MVI_GPGMM_H_
#define MVI_GPGMM_H_

#include <gpgmm.h>

#include <memory>

namespace gpgmm {

    class MemoryBase {
      public:
        MemoryBase(uint64_t size, uint64_t alignment);

        uint64_t GetSize() const;
        uint64_t GetAlignment() const;

      private:
        const uint64_t mSize;
        const uint64_t mAlignment;
    };

    class MemoryAllocation;

    class MemoryAllocator {
      public:
        virtual void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) = 0;
        virtual uint64_t ReleaseMemory(uint64_t bytesToRelease);
        virtual MemoryAllocatorStats GetStats() const;

      protected:
        MemoryAllocatorStats mStats = {};
    };

    // MemoryAllocation represents a range of memory. A MemoryAllocation object will be held alive
    // until MemoryAllocator::DeallocateMemory is called on the MemoryAllocator object from which it
    // was originally created.
    class MemoryAllocation {
      public:
        MemoryAllocation(MemoryAllocator* allocator, MemoryBase* memory);

        MemoryAllocator* GetAllocator() const;
        uint64_t GetSize() const;
        uint64_t GetAlignment() const;
        MemoryBase* GetMemory() const;

      protected:
        MemoryAllocator* mAllocator;

      private:
        MemoryBase* mMemory;
    };

}  // namespace gpgmm

#endif  // MVI_GPGMM_H_
