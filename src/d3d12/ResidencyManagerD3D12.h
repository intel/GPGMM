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

        static HRESULT CreateResidencyManager(ComPtr<ID3D12Device> device,
                                              ComPtr<IDXGIAdapter> adapter,
                                              bool isUMA,
                                              float videoMemoryBudget,
                                              uint64_t availableForResourceBudget,
                                              ResidencyManager** residencyManagerOut);

        ResidencyManager(ComPtr<ID3D12Device> device,
                         ComPtr<IDXGIAdapter3> adapter3,
                         bool isUMA,
                         float memorySegmentBudgetLimit,
                         uint64_t totalResourceBudgetLimit);

        using Cache = LinkedList<Heap>;

        struct MemorySegmentInfo {
            Cache lruCache = {};
            uint64_t budget = 0;
            uint64_t currentUsage = 0;
            uint64_t currentReservation = 0;
            uint64_t reservation = 0;
        };

        HRESULT MakeResident(const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup,
                             uint64_t sizeToMakeResident,
                             uint32_t numberOfObjectsToMakeResident,
                             ID3D12Pageable** allocations);

        MemorySegmentInfo* GetMemorySegmentInfo(
            const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        HRESULT UpdateMemorySegmentInfo(MemorySegmentInfo* memorySegmentInfo,
                                        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        ComPtr<ID3D12Device> mDevice;
        ComPtr<IDXGIAdapter3> mAdapter;
        bool mIsUMA;
        float mMemoryBudgetLimit;
        uint64_t mAvailableForResourcesBudget;
        MemorySegmentInfo mLocalMemorySegment;
        MemorySegmentInfo mNonLocalMemorySegment;

        std::unique_ptr<Fence> mFence;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
