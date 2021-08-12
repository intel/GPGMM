// Copyright 2020 The Dawn Authors
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

#ifndef GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
#define GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_

#include "src/common/LinkedList.h"

#include "src/d3d12/d3d12_platform.h"

#include <cstdint>
#include <memory>

struct ID3D12CommandList;
struct ID3D12CommandQueue;

namespace gpgmm { namespace d3d12 {

    class Fence;
    class Heap;
    class ResidencySet;

    class ResidencyManager {
      public:
        ResidencyManager(ComPtr<ID3D12Device> device, ComPtr<IDXGIAdapter3> adapter, bool isUMA);
        ~ResidencyManager();

        HRESULT LockHeap(Heap* heap);
        void UnlockHeap(Heap* heap);

        HRESULT EnsureCanAllocate(uint64_t allocationSize,
                                  const DXGI_MEMORY_SEGMENT_GROUP& memorySegment);

        HRESULT ExecuteCommandLists(ResidencySet* residencySet,
                                    ID3D12CommandQueue* d3d12Queue,
                                    ID3D12CommandList* d3d12CommandList);

        uint64_t SetExternalMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& memorySegment,
                                              uint64_t requestedReservationSize);

        void TrackResidentHeap(Heap* heap);

        void RestrictBudgetForTesting(uint64_t artificialBudgetCap);

      private:
        struct MemorySegmentInfo {
            const DXGI_MEMORY_SEGMENT_GROUP dxgiSegment;
            LinkedList<Heap> lruCache = {};
            uint64_t budget = 0;
            uint64_t usage = 0;
            uint64_t externalReservation = 0;
            uint64_t externalRequest = 0;
        };

        struct VideoMemoryInfo {
            MemorySegmentInfo local = {DXGI_MEMORY_SEGMENT_GROUP_LOCAL};
            MemorySegmentInfo nonLocal = {DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL};
        };

        MemorySegmentInfo* GetMemorySegmentInfo(const DXGI_MEMORY_SEGMENT_GROUP& memorySegment);
        HRESULT EnsureCanMakeResident(uint64_t allocationSize,
                                      MemorySegmentInfo* memorySegment,
                                      uint64_t* sizeEvictedOut);
        HRESULT RemoveSingleEntryFromLRU(MemorySegmentInfo* memorySegment, Heap** heapOut);
        HRESULT MakeAllocationsResident(MemorySegmentInfo* segment,
                                        uint64_t sizeToMakeResident,
                                        uint64_t numberOfObjectsToMakeResident,
                                        ID3D12Pageable** allocations);
        void UpdateVideoMemoryInfo();
        void UpdateMemorySegmentInfo(MemorySegmentInfo* segmentInfo);

        ComPtr<ID3D12Device> mDevice;
        ComPtr<IDXGIAdapter3> mAdapter;
        bool mRestrictBudgetForTesting = false;
        bool mIsUMA;
        VideoMemoryInfo mVideoMemoryInfo = {};

        std::unique_ptr<Fence> mFence;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
