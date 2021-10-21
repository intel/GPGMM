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

namespace gpgmm { namespace d3d12 {

    class Fence;
    class Heap;
    class ResidencySet;
    class ResourceAllocator;

    typedef enum RESIDENCY_FLAGS {

        // Disables all flags. Enabled by default.
        RESIDENCY_FLAG_NONE = 0x0,

    } RESIDENCY_FLAGS;

    struct RESIDENCY_DESC {
        // Device and adapter used by this residency manager. The adapter must support DXGI 1.4
        // to use residency. Required parameters.
        Microsoft::WRL::ComPtr<ID3D12Device> Device;
        Microsoft::WRL::ComPtr<IDXGIAdapter3> Adapter;

        RESIDENCY_FLAGS Flags = RESIDENCY_FLAG_NONE;

        // Determines if video memory segments are unified or shared. Use CheckFeatureSupport
        // to check for support. Required parameter.
        bool IsUMA;

        // Maximum video memory available to budget by the allocator, expressed as a
        // percentage. By default, the max video memory available is 0.95 or 95% of video memory
        // can be budgeted, always leaving 5% for the OS and other applications.
        float MaxVideoMemoryBudget;

        // Video memory available to budget for resources.
        uint64_t AvailableVideoMemoryForResources;
    };

    class ResidencyManager {
      public:
        static HRESULT CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                              ResidencyManager** residencyManager);

        ~ResidencyManager();

        HRESULT LockHeap(Heap* heap);
        HRESULT UnlockHeap(Heap* heap);

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

        HRESULT InsertHeap(Heap* heap);

      private:
        friend ResourceAllocator;

        ResidencyManager(ComPtr<ID3D12Device> device, ComPtr<IDXGIAdapter3> adapter3);

        struct VideoMemorySegmentInfo {
            const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup;
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
            bool isUMA = false;
            float budget = 0;
            uint64_t availableForResources = 0;
        };

        HRESULT EvictHeap(const VideoMemorySegmentInfo& videoMemorySegment, Heap** heapOut);
        HRESULT MakeResident(const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup,
                             uint64_t sizeToMakeResident,
                             uint32_t numberOfObjectsToMakeResident,
                             ID3D12Pageable** allocations);

        VideoMemorySegmentInfo* GetVideoMemorySegment(
            const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        HRESULT UpdateVideoMemorySegment(VideoMemorySegmentInfo* videoMemorySegment);

        ComPtr<ID3D12Device> mDevice;
        ComPtr<IDXGIAdapter3> mAdapter;
        VideoMemoryInfo mVideoMemory = {};

        std::unique_ptr<Fence> mFence;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
