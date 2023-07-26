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

#include <cstdint>
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

    class MemoryAllocationBase;

    class MemoryAllocatorBase {
      public:
        virtual void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) = 0;
        virtual uint64_t ReleaseMemory(uint64_t bytesToRelease);
    };

    // MemoryAllocationBase represents a range of memory. A MemoryAllocationBase object will be held
    // alive until MemoryAllocatorBase::DeallocateMemory is called on the MemoryAllocatorBase object
    // from which it was originally created.
    class MemoryAllocationBase {
      public:
        MemoryAllocationBase(MemoryAllocatorBase* allocator, MemoryBase* memory);

        MemoryAllocatorBase* GetAllocator() const;
        uint64_t GetSize() const;
        uint64_t GetAlignment() const;
        MemoryBase* GetMemory() const;

      protected:
        MemoryAllocatorBase* mAllocator;

      private:
        MemoryBase* mMemory;
    };

}  // namespace gpgmm

#endif  // MVI_GPGMM_H_
