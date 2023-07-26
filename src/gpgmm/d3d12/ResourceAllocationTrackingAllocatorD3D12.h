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

#ifndef GPGMM_D3D12_RESOURCEALLOCATIONTRACKINGALLOCATORD3D12_H_
#define GPGMM_D3D12_RESOURCEALLOCATIONTRACKINGALLOCATORD3D12_H_

#include "gpgmm/common/MemoryAllocator.h"
#include "gpgmm/common/MemoryCache.h"

namespace gpgmm::d3d12 {

    class ResourceAllocation;

    // ResourceAllocationTrackingAllocator tracks "live" allocations so they can be reported if
    // leaked. A "live" allocation means the allocation was created (allocated) but not released
    // (de-allocated).
    class ResourceAllocationTrackingAllocator final : public MemoryAllocatorBase {
      public:
        ResourceAllocationTrackingAllocator() = default;

        void TrackAllocation(ResourceAllocation* allocation);
        void ReportLiveAllocations() const;
        void ReleaseLiveAllocationsForTesting();

      private:
        // ObjectBase interface
        DEFINE_OBJECT_BASE_OVERRIDES(DebugResourceAllocator)

        void DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) override;

        class ResourceAllocationEntry {
          public:
            explicit ResourceAllocationEntry(ResourceAllocation* allocation);  // For lookup
            ResourceAllocationEntry(ResourceAllocation* allocation, MemoryAllocatorBase* allocator);

            MemoryAllocatorBase* GetAllocator() const;
            ResourceAllocation* GetAllocation() const;
            size_t GetKey() const;

          private:
            ResourceAllocation* mAllocation = nullptr;
            MemoryAllocatorBase* mAllocator = nullptr;
        };

        MemoryCache<ResourceAllocationEntry> mLiveAllocations = {};
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATIONTRACKINGALLOCATORD3D12_H_
