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

#ifndef SRC_GPGMM_D3D12_CAPSD3D12_H_
#define SRC_GPGMM_D3D12_CAPSD3D12_H_

#include "gpgmm/common/GPUInfo.h"
#include "gpgmm/d3d12/D3D12Platform.h"
#include "gpgmm/utils/Limits.h"

#include <cstdint>

namespace gpgmm::d3d12 {

    class Caps {
      public:
        static HRESULT CreateCaps(ID3D12Device* device, IDXGIAdapter* adapter, Caps** capsOut);

        // Largest resource size that this device can make available.
        uint64_t GetMaxResourceSize() const;

        // Largest resource heap that this device can make available.
        uint64_t GetMaxResourceHeapSize() const;

        // Allows a resource heap to be created without being resident.
        bool IsCreateHeapNotResidentSupported() const;

        // Allows a resource to be shared between multiple command queues.
        bool IsResourceAllocationWithinCoherent() const;

        // Specifies if the adapter uses a Unified Memory Architecture (UMA).
        bool IsAdapterUMA() const;

        // Specifies if the UMA adapter is also cache-coherent.
        bool IsAdapterCacheCoherentUMA() const;

        // Specifies if a texture and buffer can belong in the same heap.
        D3D12_RESOURCE_HEAP_TIER GetMaxResourceHeapTierSupported() const;

        uint64_t GetMaxSegmentSize(DXGI_MEMORY_SEGMENT_GROUP heapSegment) const;

      private:
        Caps() = default;

        uint64_t mMaxResourceSize = kInvalidSize;
        uint64_t mMaxResourceHeapSize = kInvalidSize;
        uint64_t mSharedSegmentSize = kInvalidSize;
        uint64_t mDedicatedSegmentSize = kInvalidSize;
        D3D12_RESOURCE_HEAP_TIER mMaxResourceHeapTier = D3D12_RESOURCE_HEAP_TIER_1;
        bool mIsCreateHeapNotResidentSupported = false;
        bool mIsResourceAllocationWithinCoherent = false;
        bool mIsAdapterUMA = false;
        bool mIsAdapterCacheCoherentUMA = false;
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_CAPSD3D12_H_
