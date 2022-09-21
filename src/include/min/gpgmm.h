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

#ifndef INCLUDE_MIN_GPGMM_H_
#define INCLUDE_MIN_GPGMM_H_

#include <cstdint>
#include <memory>

namespace gpgmm {

    class MemoryBase {
      public:
        MemoryBase(uint64_t size, uint64_t alignment);
        virtual ~MemoryBase();

        uint64_t GetSize() const;
        uint64_t GetAlignment() const;

      private:
        const uint64_t mSize;
        const uint64_t mAlignment;
    };

    struct MemoryAllocatorInfo {
        uint32_t UsedBlockCount;
        uint64_t UsedBlockUsage;
        uint32_t UsedMemoryCount;
        uint64_t UsedMemoryUsage;
        uint64_t FreeMemoryUsage;
        uint64_t PrefetchedMemoryMisses;
        uint64_t PrefetchedMemoryMissesEliminated;
        uint64_t SizeCacheMisses;
        uint64_t SizeCacheHits;
    };

    class MemoryAllocation;

    class MemoryAllocator {
      public:
        virtual void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) = 0;
        virtual uint64_t ReleaseMemory(uint64_t bytesToRelease);
        virtual MemoryAllocatorInfo GetInfo() const;

      protected:
        MemoryAllocatorInfo mInfo = {};
    };

    struct MemoryAllocationInfo {
        uint64_t SizeInBytes;
        uint64_t Alignment;
    };

    enum AllocationMethod {
        kUndefined = 0,
        kStandalone = 1,
        kSubAllocated = 2,
        kSubAllocatedWithin = 3,
    };

    struct MemoryBlock {
        uint64_t Offset;
        uint64_t Size;
    };

    class MemoryAllocation {
      public:
        MemoryAllocation(MemoryAllocator* allocator, MemoryBase* memory, uint64_t requestSize);

        virtual ~MemoryAllocation();

        MemoryAllocation(const MemoryAllocation&);
        MemoryAllocation& operator=(const MemoryAllocation&);
        bool operator==(const MemoryAllocation&) const;
        bool operator!=(const MemoryAllocation& other) const;

        MemoryAllocationInfo GetInfo() const;
        MemoryBase* GetMemory() const;
        uint8_t* GetMappedPointer() const;
        MemoryAllocator* GetAllocator() const;
        uint64_t GetSize() const;
        uint64_t GetRequestSize() const;
        uint64_t GetAlignment() const;
        uint64_t GetOffset() const;
        AllocationMethod GetMethod() const;
        MemoryBlock* GetBlock() const;

      protected:
        MemoryAllocator* mAllocator;

      private:
        MemoryBase* mMemory;
        uint64_t mRequestSize;
    };

}  // namespace gpgmm

#endif  // INCLUDE_MIN_GPGMM_H_
