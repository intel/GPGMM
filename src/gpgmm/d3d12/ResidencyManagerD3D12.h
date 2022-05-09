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

#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "gpgmm/utils/LinkedList.h"
#include "include/gpgmm_export.h"

#include <memory>
#include <mutex>

namespace gpgmm { namespace d3d12 {

    class Fence;
    class Heap;
    class ResidencySet;

    /** \struct RESIDENCY_DESC
     Specify parameters when creating a residency manager.
     */
    struct RESIDENCY_DESC {
        /** \brief Specifies the device used by this residency manager.
        Required parameter. Use CreateDevice get the device.
        */
        Microsoft::WRL::ComPtr<ID3D12Device> Device;

        /** \brief Specifies the adapter used by this residency manager.

        Requires DXGI 1.4 due to IDXGIAdapter3::QueryVideoMemoryInfo.

        Required parameter. Use EnumAdapters to get the adapter.
        */
        Microsoft::WRL::ComPtr<IDXGIAdapter3> Adapter;

        /** \brief Specifies if unified memory architecture (UMA) support is enabled.

        Used to determine if residency manager must manage local and non-local segments seperately
        or not.

        Required parameter. Use CheckFeatureSupport to determine if supported.
        */
        bool IsUMA;

        /** \brief Total budget of video memory, expressed as a percentage.

        Optional parameter. When 0 is specified, the API will automatically set the video
        memory budget to 95%, leaving 5% for the OS and other applications.
        */
        float VideoMemoryBudget;

        /** \brief Specify the budget, in bytes, for residency.

        Allows a fixed budget to be artifically set for testing purposes.

        Optional parameter. When 0 is specified, the API will not restrict the residency manager
        budget.
        */
        uint64_t Budget;

        /** \brief Specifies the amount of memory, in bytes, to evict from residency at once,
        should there not be enough budget left.

        Optional parameter. When 0 is specified, the API will automatically set the video memory
        evict size to 50MB.
        */
        uint64_t EvictBatchSize;
    };

    class GPGMM_EXPORT ResidencyManager final : public IUnknownImpl {
      public:
        /** \brief  Create residency residency manager to manage video memory.

        @param descriptor A reference to RESIDENCY_DESC structure that describes the residency
        manager.
        @param[out] residencyManagerOut Pointer to a memory block that recieves a pointer to the
        residency Manager. Pass NULL to test if residency Manager creation would succeed, but not
        actually create the residency Manager. If NULL is passed and residency Manager creating
        would succeed, S_FALSE is returned.
        */
        static HRESULT CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                              ResidencyManager** residencyManagerOut);

        ~ResidencyManager();

        /** \brief  Locks the specified heap.

        Locking a heap means the residency manager will never evict it when over budget.

        @param heap A pointer to the heap being locked.
        */
        HRESULT LockHeap(Heap* heap);

        /** \brief  Unlocks the specified heap.

        Unlocking a heap allows the residency manager will evict it when over budget.

        @param heap A pointer to the heap being unlocked.
        */
        HRESULT UnlockHeap(Heap* heap);

        /** \brief  Add or insert the specify heap.

        Inserting a heap means to have it managed by this residency manager.

        @param heap A pointer to the heap being managed.
        */
        HRESULT InsertHeap(Heap* heap);

        /** \brief  Evict memory per segment.

        Evicts until the budget is under the specified size.

        @param evictSizeInBytes Target size, in bytes, to be under budget.
        @param memorySegmentGroup Memory segment to evict from.
        */
        HRESULT Evict(uint64_t evictSizeInBytes,
                      const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup);

        /** \brief  Execute command lists using residency managed heaps.

        Submits an array of command lists and residency sets for the specified command queue.

        @param queue The command queue to submit to.
        @param commandLists The array of ID3D12CommandList command lists to be executed.
        @param residencySets The array of ResidencySet residency sets to make resident.
        @param count The size of commandLists and residencySets arrays.
        */
        HRESULT ExecuteCommandLists(ID3D12CommandQueue* queue,
                                    ID3D12CommandList* const* commandLists,
                                    ResidencySet* const* residencySets,
                                    uint32_t count);

        /** \brief  Sets video memory reservation.

        A reservation is the lowest amount of physical memory the application need to continue
        operation safely.

        @param memorySegmentGroup Memory segment to reserve.
        @param reservation Amount of memory to reserve, in bytes.
        @param[out] reservationOut the amount of memory reserved, which may be less then the
        |reservation| when under video memory pressure.
        */
        HRESULT SetVideoMemoryReservation(const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                                          uint64_t reservation,
                                          uint64_t* reservationOut = nullptr);

      private:
        ResidencyManager(const RESIDENCY_DESC& descriptor, std::unique_ptr<Fence> fence);

        HRESULT EvictInternal(uint64_t evictSizeInBytes,
                              const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
                              uint64_t* evictedSizeInBytesOut = nullptr);

        HRESULT InsertHeapInternal(Heap* heap);

        const char* GetTypename() const;

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
                                     DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfo) const;

        // Query and set the video memory limits for all segments.
        HRESULT UpdateVideoMemorySegments();

        ComPtr<ID3D12Device> mDevice;
        ComPtr<IDXGIAdapter3> mAdapter;
        ComPtr<ID3D12Device3> mDevice3;

        std::unique_ptr<Fence> mFence;

        const float mVideoMemoryBudget;
        const uint64_t mBudget;
        const uint64_t mEvictBatchSize;
        const bool mIsUMA;

        VideoMemorySegment mLocalVideoMemorySegment;
        VideoMemorySegment mNonLocalVideoMemorySegment;

        std::mutex mMutex;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESIDENCYMANAGERD3D12_H_
