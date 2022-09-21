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

#ifndef GPGMM_D3D12_DEBUGRESOURCEALLOCATORD3D12_H_
#define GPGMM_D3D12_DEBUGRESOURCEALLOCATORD3D12_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/MemoryCache.h"

namespace gpgmm::d3d12 {

    class ResourceAllocation;

    /** \brief DebugResourceAllocator tracks "live" allocations so they can be reported if leaked.

    A "live" allocation means the allocation was created (allocated) but not released
    (de-allocated).

    Use `gpgmm_enable_allocator_leak_checks = true` to always report for leaks.
    */
    class DebugResourceAllocator final : public MemoryAllocator {
      public:
        DebugResourceAllocator() = default;

        /** \brief Add a "live" allocation.

        @param allocation A pointer to a ResourceAllocation to track.
        */
        void AddLiveAllocation(ResourceAllocation* allocation);

        /** \brief Report "live" allocations.

        Dumps outstanding or "live" allocations.
        */
        void ReportLiveAllocations() const;

      private:
        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        const char* GetTypename() const override;

        class ResourceAllocationEntry {
          public:
            explicit ResourceAllocationEntry(ResourceAllocation* allocation);  // For lookup
            ResourceAllocationEntry(ResourceAllocation* allocation, MemoryAllocator* allocator);

            MemoryAllocator* GetAllocator() const;
            ResourceAllocation* GetAllocation() const;
            size_t GetKey() const;

          private:
            ResourceAllocation* mAllocation = nullptr;
            MemoryAllocator* mAllocator = nullptr;
        };

        MemoryCache<ResourceAllocationEntry> mLiveAllocations = {};
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_DEBUGRESOURCEALLOCATORD3D12_H_
