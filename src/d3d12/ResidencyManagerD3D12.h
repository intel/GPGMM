// Copyright 2020 The Dawn Authors
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

#ifndef GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
#define GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_

#include "../common/LinkedList.h"

#include "src/d3d12/d3d12_platform.h"

#include <cstdint>
#include <memory>

struct ID3D12CommandList;
struct ID3D12CommandQueue;

namespace gpgmm { namespace d3d12 {

    class Fence;
    class Heap;
    class ResidencySet;
    class ResourceAllocator;

    class ResidencyManager {
      public:
        ~ResidencyManager();

        HRESULT LockHeap(Heap* heap);
        void UnlockHeap(Heap* heap);

        HRESULT Evict(uint64_t allocationSize,
                      const DXGI_MEMORY_SEGMENT_GROUP& dxgiMemorySegmentGroup,
                      uint64_t* sizeEvictedOut = nullptr);

        HRESULT ExecuteCommandLists(ID3D12CommandQueue* d3d12Queue,
                                    ID3D12CommandList** d3d12CommandLists,
                                    ResidencySet** residencySets,
                                    uint32_t count);

        HRESULT SetVideoMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& dxgiMemorySegmentGroup,
                                          uint64_t reservation,
                                          uint64_t* reservationOut = nullptr);

        HRESULT InsertHeap(Heap* heap);

      private:
        friend ResourceAllocator;

        ResidencyManager(ComPtr<ID3D12Device> device,
                         ComPtr<IDXGIAdapter3> adapter3,
                         bool isUMA,
                         float memorySegmentBudgetLimit,
                         uint64_t totalResourceBudgetLimit);

        struct VideoMemorySegmentInfo {
            const DXGI_MEMORY_SEGMENT_GROUP dxgiMemorySegmentGroup;
            LinkedList<Heap> lruCache = {};
            uint64_t budget = 0;
            uint64_t usage = 0;
            uint64_t externalReservation = 0;
            uint64_t externalRequest = 0;
        };

        struct VideoMemoryInfo {
            VideoMemorySegmentInfo localVideoMemorySegment = {DXGI_MEMORY_SEGMENT_GROUP_LOCAL};
            VideoMemorySegmentInfo nonLocalVideoMemorySegment = {
                DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL};
        };

        HRESULT EvictHeap(VideoMemorySegmentInfo* videoMemorySegment, Heap** heapOut);
        HRESULT MakeResident(const DXGI_MEMORY_SEGMENT_GROUP dxgiMemorySegmentGroup,
                             uint64_t sizeToMakeResident,
                             uint64_t numberOfObjectsToMakeResident,
                             ID3D12Pageable** allocations);

        VideoMemorySegmentInfo* GetVideoMemorySegmentInfo(
            const DXGI_MEMORY_SEGMENT_GROUP& dxgiMemorySegmentGroup);
        void UpdateVideoMemorySegmentInfo(VideoMemorySegmentInfo* videoMemorySegment);

        ComPtr<ID3D12Device> mDevice;
        ComPtr<IDXGIAdapter3> mAdapter;
        bool mIsUMA;
        float mVideoMemoryBudgetLimit;
        uint64_t mTotalResourceBudgetLimit;
        VideoMemoryInfo mVideoMemoryInfo = {};

        std::unique_ptr<Fence> mFence;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
