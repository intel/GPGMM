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

#ifndef GPGMM_D3D12_HEAPD3D12_H_
#define GPGMM_D3D12_HEAPD3D12_H_

#include "gpgmm/common/Memory.h"
#include "gpgmm/d3d12/DebugObjectD3D12.h"
#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/LinkedList.h"
#include "gpgmm/utils/RefCount.h"
#include "include/gpgmm_export.h"

#include <functional>  // for std::function
#include <memory>

namespace gpgmm::d3d12 {

    class ResidencySet;
    class ResidencyManager;
    class ResourceAllocator;

    /** \enum RESIDENCY_SEGMENT
    Specifies which type of segment the heap belongs to.

    RESIDENCY_SEGMENT is equivelent to DXGI_MEMORY_SEGMENT_GROUP but also has
    RESIDENCY_SEGMENT_UNKNOWN.
    */
    enum RESIDENCY_SEGMENT {
        RESIDENCY_SEGMENT_UNKNOWN,
        RESIDENCY_SEGMENT_LOCAL,
        RESIDENCY_SEGMENT_NON_LOCAL,
    };

    /** \struct HEAP_INFO
    Additional information about the heap.
    */
    struct HEAP_INFO {
        /** \brief Check if the heap is resident or not.
         */
        bool IsResident;

        /** \brief The number of sub-allocations made using this heap.

        A count of 0 means the entire heap is being used.
        */
        uint64_t SubAllocatedRefs;

        /** \brief The pool this heap is assigned to.

        A NULL pool means this heap cannot be recycled by GPGMM.
        */
        MemoryPool* MemoryPool;
    };

    /** \struct HEAP_DESC
    Specifies properties of a managed heap.
    */
    struct HEAP_DESC {
        /** \brief Created size of the heap, in bytes.

        Must be non-zero. SizeInBytes is always a multiple of the alignment.
        */
        uint64_t SizeInBytes;

        /** \brief Created alignment of the heap, in bytes.

        Must be non-zero.
        */
        uint64_t Alignment;

        /** \brief Specifies the type of heap.

        When resident, heaps reside in a particular video segment.
        */
        D3D12_HEAP_TYPE HeapType;

        /** \brief Requires the heap to be created in budget.
         */
        bool AlwaysInBudget;

        /** \brief Specifies to leave the heap unmanaged by GPGMM.

        External heaps are not supported for residency.
        */
        bool IsExternal;

        /** \brief Specifies the memory segment to use for residency.

        Allows any heap to specify a segment which does not have a attributed heap type.
        */
        RESIDENCY_SEGMENT MemorySegment;

        /** \brief Debug name associated with the heap.
         */
        std::string DebugName;
    };

    /** \brief Callback function used to create a ID3D12Pageable.

    For example, to create a ID3D12Heap:

    \code
    auto callback = [heapDesc](ID3D12Pageable** ppPageableOut) -> HRESULT {
        ComPtr<ID3D12Heap> heap;
        ReturnIfFailed(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap)));
        *ppPageableOut = heap.Detach();
    };
    \endcode
    */
    using CreateHeapFn = std::function<HRESULT(ID3D12Pageable** ppPageableOut)>;

    /** \brief Heap is used to represent managed ID3D12Heap or ID3D12Resource that has an implicit
    heap (owned by D3D) for a committed resource, in the ResidencyManager's residency cache.

    Heap serves as a node within the ResidencyManager's residency cache. This node is inserted into
    the cache when it is first created, and any time it is scheduled to be used by the GPU. This
    node is removed from the cache when it is evicted from video memory due to budget constraints,
    or when the memory is released.
    */
    class GPGMM_EXPORT Heap final : public MemoryBase,
                                    public DebugObject,
                                    public IUnknownImpl,
                                    public LinkNode<Heap> {
      public:
        /** \brief  Create a heap managed by GPGMM.

        Unlike a normal D3D12 heap, a heap managed by GPGMM means it will be tracked for residency
        purposes. A heap managed by GPGMM represents either a 1) committed resource backed by
        implicit D3D12 heap OR 2) an explicit D3D12 heap used with placed resources.

        @param descriptor A reference to HEAP_DESC structure that describes the heap.
        @param pResidencyManager A pointer to the ResidencyManager used to manage this heap.
        @param createHeapFn  A callback function which creates a ID3D12Pageable derived type.
        @param[out] ppHeapOut Pointer to a memory block that recieves a pointer to the
        heap.
        */
        static HRESULT CreateHeap(const HEAP_DESC& descriptor,
                                  ResidencyManager* const pResidencyManager,
                                  CreateHeapFn&& createHeapFn,
                                  Heap** ppHeapOut);

        ~Heap() override;

        /** \brief Returns a ComPtr object that represents the interface specified.

        For example, to get a ID3D12Heap:

        \code
        ComPtr<ID3D12Heap> heap;
        HRESULT hr = resourceHeap->As(&heap);
        \endcode

        \return Error HRESULT if the specified interface was not represented by the
        heap.
        */
        template <typename T>
        HRESULT As(Microsoft::WRL::Details::ComPtrRef<ComPtr<T>> ptr) const {
            return mPageable.As(ptr);
        }

        /** \brief Determine if the heap is resident or not.

        \return True if the heap is resident, false if not.
        */
        bool IsResident() const;

        /** \brief Get information about the heap.

        \return HEAP_INFO with the latest information.
        */
        HEAP_INFO GetInfo() const;

        // Testing only.
        bool IsInResidencyLRUCache() const;
        bool IsResidencyLocked() const;

      private:
        friend ResidencyManager;
        friend ResourceAllocator;

        Heap(ComPtr<ID3D12Pageable> pageable,
             const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
             uint64_t size,
             uint64_t alignment,
             bool isExternal);

        HRESULT SetDebugNameImpl(const std::string& name) override;
        const char* GetTypename() const;
        DXGI_MEMORY_SEGMENT_GROUP GetMemorySegmentGroup() const;

        // The residency manager must know the last fence value that any portion of the pageable was
        // submitted to be used so that we can ensure this pageable stays resident in memory at
        // least until that fence has completed.
        uint64_t GetLastUsedFenceValue() const;
        void SetLastUsedFenceValue(uint64_t fenceValue);

        // Locks residency to ensure the heap cannot be evicted (ex. shader-visible descriptor
        // heaps or mapping resources).
        void AddResidencyLockRef();
        void ReleaseResidencyLock();

        ComPtr<ID3D12Pageable> mPageable;

        // mLastUsedFenceValue denotes the last time this pageable was submitted to the GPU.
        uint64_t mLastUsedFenceValue = 0;
        DXGI_MEMORY_SEGMENT_GROUP mMemorySegmentGroup;
        RefCounted mResidencyLock;
        bool mIsExternal;
    };
}  // namespace gpgmm::d3d12

#endif
