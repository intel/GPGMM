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

#include "gpgmm/common/LinkedList.h"
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "include/gpgmm_export.h"

#include <memory>

namespace gpgmm { namespace d3d12 {

    class Fence;
    class Heap;
    class ResidencySet;
    class ResourceAllocator;

    class GPGMM_EXPORT ResidencyManager : public IUnknownImpl {
      public:
        ~ResidencyManager();

        HRESULT LockHeap(Heap* heap);
        HRESULT UnlockHeap(Heap* heap);
        HRESULT InsertHeap(Heap* heap);

        HRESULT Evict(uint64_t sizeToMakeResident,
                      const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                      uint64_t* sizeEvictedOut = nullptr);

        HRESULT ExecuteCommandLists(ID3D12CommandQueue* queue,
                                    ID3D12CommandList* const* commandLists,
                                    ResidencySet* const* residencySets,
                                    uint32_t count);

        HRESULT SetVideoMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                          uint64_t reservation,
                                          uint64_t* reservationOut = nullptr);

      private:
        friend ResourceAllocator;

        static HRESULT CreateResidencyManager(ComPtr<ID3D12Device> device,
                                              ComPtr<IDXGIAdapter> adapter,
                                              bool isUMA,
                                              float videoMemoryBudget,
                                              uint64_t availableForResourceBudget,
                                              uint64_t videoMemoryEvictSize,
                                              ResidencyManager** residencyManagerOut);

        ResidencyManager(ComPtr<ID3D12Device> device,
                         ComPtr<IDXGIAdapter3> adapter3,
                         std::unique_ptr<Fence> fence,
                         bool isUMA,
                         float memorySegmentBudgetLimit,
                         uint64_t totalResourceBudgetLimit,
                         uint64_t videoMemoryEvictSize);

        using LRUCache = LinkedList<Heap>;

        struct VideoMemorySegment {
            LRUCache cache = {};
            DXGI_QUERY_VIDEO_MEMORY_INFO Info = {};
        };

        HRESULT MakeResident(const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup,
                             uint64_t sizeToMakeResident,
                             uint32_t numberOfObjectsToMakeResident,
                             ID3D12Pageable** allocations);

        DXGI_QUERY_VIDEO_MEMORY_INFO* GetVideoMemorySegmentInfo(
            const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        LRUCache* GetVideoMemorySegmentCache(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        HRESULT QueryVideoMemoryInfo(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                     DXGI_QUERY_VIDEO_MEMORY_INFO* videoMemoryInfo) const;

        ComPtr<ID3D12Device> mDevice;
        ComPtr<IDXGIAdapter3> mAdapter;

        std::unique_ptr<Fence> mFence;

        const float mMaxVideoMemoryBudget;
        const uint64_t mTotalResourceBudgetLimit;
        const uint64_t mVideoMemoryEvictSize;

        VideoMemorySegment mLocalVideoMemorySegment;
        VideoMemorySegment mNonLocalVideoMemorySegment;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
