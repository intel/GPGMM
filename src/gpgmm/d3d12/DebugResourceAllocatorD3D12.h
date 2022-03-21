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

#ifndef GPGMM_D3D12_DEBUGRESOURCEALLOCATORD3D12_H_
#define GPGMM_D3D12_DEBUGRESOURCEALLOCATORD3D12_H_

#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/MemoryCache.h"

namespace gpgmm { namespace d3d12 {

    class ResourceAllocation;

    // DebugResourceAllocator tracks live allocations (ie. created allocations, not yet
    // deallocated) so they can be reported if leaked.
    class DebugResourceAllocator : public MemoryAllocator {
      public:
        DebugResourceAllocator() = default;

        void AddLiveAllocation(ResourceAllocation* allocation);
        void ReportLiveAllocations() const;

      private:
        void DeallocateMemory(MemoryAllocation* allocation) override;

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

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_DEBUGRESOURCEALLOCATORD3D12_H_
