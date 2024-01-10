// Copyright 2020 The Dawn Authors
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

#include "gpgmm/d3d12/ResidencyHeapD3D12.h"

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/LogD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm::d3d12 {

    namespace {

        // Returns the resource heap flags or E_INVALIDARG, when the memory type doesn't allow
        // resources.
        HRESULT GetResourceHeapFlags(ComPtr<ID3D12Pageable> pageable, D3D12_HEAP_FLAGS* heapFlags) {
            ComPtr<ID3D12Heap> heap;
            if (SUCCEEDED(pageable.As(&heap))) {
                *heapFlags = heap->GetDesc().Flags;
                return S_OK;
            }

            ComPtr<ID3D12Resource> committedResource;
            if (SUCCEEDED(pageable.As(&committedResource))) {
                GPGMM_RETURN_IF_FAILED(committedResource->GetHeapProperties(nullptr, heapFlags),
                                       GetDevice(committedResource.Get()).Get());
                return S_OK;
            }

            return E_INVALIDARG;
        }

        HEAP_ALLOCATION_INFO GetResourceHeapAllocationInfo(ComPtr<ID3D12Pageable> pageable) {
            ComPtr<ID3D12Heap> heap;
            if (SUCCEEDED(pageable.As(&heap))) {
                const D3D12_HEAP_DESC desc = heap->GetDesc();
                return {desc.SizeInBytes, desc.Alignment};
            }

            ComPtr<ID3D12Resource> committedResource;
            if (SUCCEEDED(pageable.As(&committedResource))) {
                const D3D12_RESOURCE_DESC desc = committedResource->GetDesc();
                const D3D12_RESOURCE_ALLOCATION_INFO info =
                    GetDevice(committedResource.Get())->GetResourceAllocationInfo(0, 1, &desc);
                return info;
            }

            return {kInvalidSize, kInvalidSize};
        }

        HEAP_ALLOCATION_INFO GetDescriptorHeapAllocationInfo(ComPtr<ID3D12Pageable> pageable) {
            ComPtr<ID3D12DescriptorHeap> heap;
            if (SUCCEEDED(pageable.As(&heap))) {
                const D3D12_DESCRIPTOR_HEAP_DESC desc = heap->GetDesc();
                const uint64_t sizePerDescriptor =
                    GetDevice(heap.Get())->GetDescriptorHandleIncrementSize(desc.Type);
                return {desc.NumDescriptors * sizePerDescriptor, sizePerDescriptor};
            }

            return {kInvalidSize, kInvalidSize};
        }

        HEAP_ALLOCATION_INFO GetHeapAllocationInfo(ComPtr<ID3D12Pageable> pageable) {
            const D3D12_RESOURCE_ALLOCATION_INFO resourceHeapInfo =
                GetResourceHeapAllocationInfo(pageable);
            if (resourceHeapInfo.SizeInBytes != kInvalidSize) {
                return resourceHeapInfo;
            }

            const HEAP_ALLOCATION_INFO descriptorHeapInfo =
                GetDescriptorHeapAllocationInfo(pageable);
            if (descriptorHeapInfo.SizeInBytes != kInvalidSize) {
                return descriptorHeapInfo;
            }

            return {kInvalidSize, kInvalidSize};
        }

    }  // namespace

    RESIDENCY_HEAP_FLAGS GetHeapFlags(D3D12_HEAP_FLAGS heapFlags, bool alwaysCreatedInBudget) {
        if (alwaysCreatedInBudget) {
            return RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET | RESIDENCY_HEAP_FLAG_CREATE_RESIDENT;
        }

        return RESIDENCY_HEAP_FLAG_CREATE_RESIDENT;
    }

    HRESULT CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                IResidencyManager* const pResidencyManager,
                                CreateHeapFn createHeapFn,
                                void* pCreateHeapContext,
                                IResidencyHeap** ppResidencyHeapOut) {
        return ResidencyHeap::CreateResidencyHeap(descriptor, pResidencyManager, createHeapFn,
                                                  pCreateHeapContext, ppResidencyHeapOut);
    }

    HRESULT CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                IResidencyManager* const pResidencyManager,
                                ID3D12Pageable* pPageable,
                                IResidencyHeap** ppResidencyHeapOut) {
        return ResidencyHeap::CreateResidencyHeap(descriptor, pResidencyManager, pPageable,
                                                  ppResidencyHeapOut);
    }

    // static
    HRESULT ResidencyHeap::CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                               IResidencyManager* const pResidencyManager,
                                               ID3D12Pageable* pPageable,
                                               IResidencyHeap** ppResidencyHeapOut) {
        GPGMM_TRACE_EVENT_OBJECT_CALL(
            "Heap.CreateResidencyHeap",
            (RESIDENCY_HEAP_CREATE_RESIDENCY_HEAP_PARAMS{descriptor, pPageable}));

        GPGMM_RETURN_IF_NULL(pPageable);

        RESIDENCY_HEAP_DESC newDescriptor = descriptor;
        const HEAP_ALLOCATION_INFO heapInfo = GetHeapAllocationInfo(pPageable);
        if (descriptor.SizeInBytes == 0) {
            newDescriptor.SizeInBytes = heapInfo.SizeInBytes;
        }

        if (newDescriptor.SizeInBytes == kInvalidSize) {
            ErrorLog(ErrorCode::kInvalidArgument) << "Heap size for residency was invalid";
            return E_INVALIDARG;
        }

        if (descriptor.Alignment == 0) {
            newDescriptor.Alignment = heapInfo.Alignment;
        }

        if (newDescriptor.Alignment == kInvalidSize) {
            ErrorLog(ErrorCode::kInvalidArgument) << "Heap alignment for residency was invalid.";
            return E_INVALIDARG;
        }

        ResidencyManager* residencyManager = FromAPI(pResidencyManager);

        std::unique_ptr<ResidencyHeap> heap(
            new ResidencyHeap(residencyManager, pPageable, newDescriptor));

        if (residencyManager != nullptr) {
            // Resource heaps created without the "create not resident" flag are always
            // resident.
            D3D12_HEAP_FLAGS resourceHeapFlags = D3D12_HEAP_FLAG_NONE;
            if (SUCCEEDED(GetResourceHeapFlags(pPageable, &resourceHeapFlags))) {
                if (!(resourceHeapFlags & D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT)) {
                    heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_RESIDENT);
                } else {
                    heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_EVICTED);
                }
            }

            // Heap created not resident requires no budget to be created.
            if (heap->GetInfo().Status == RESIDENCY_HEAP_STATUS_EVICTED &&
                (newDescriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET)) {
                ErrorLog(ErrorCode::kInvalidArgument, heap.get())
                    << "Creating a heap always in budget cannot be used with "
                       "D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT.";
                return E_INVALIDARG;
            }

            // Only heap types that are known to be created resident are eligable for evicition and
            // should be always inserted in the residency cache. For other heap types (eg.
            // descriptor heap), they must be manually locked and unlocked to be inserted into the
            // residency cache.
            if (heap->GetInfo().Status != RESIDENCY_HEAP_STATUS_UNKNOWN) {
                GPGMM_RETURN_IF_FAILED(residencyManager->InsertHeap(heap.get()));
            } else {
                if (newDescriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_RESIDENT) {
                    GPGMM_RETURN_IF_FAILED(heap->Lock());
                    GPGMM_RETURN_IF_FAILED(heap->Unlock());
                    ASSERT(heap->GetInfo().Status == RESIDENCY_HEAP_STATUS_RESIDENT);
                }
            }

            if (newDescriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_LOCKED) {
                GPGMM_RETURN_IF_FAILED(heap->Lock());
                ASSERT(heap->GetInfo().Status == RESIDENCY_HEAP_STATUS_RESIDENT);
            }

        } else {
            if (newDescriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_RESIDENT) {
                WarnLog(MessageId::kPerformanceWarning, heap.get())
                    << "RESIDENCY_HEAP_FLAG_CREATE_RESIDENT was specified but had no effect "
                       "becauase residency management is not being used.";
            }

            // Locking heaps requires residency management.
            if (newDescriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_LOCKED) {
                ErrorLog(ErrorCode::kInvalidArgument, heap.get())
                    << "RESIDENCY_HEAP_FLAG_CREATE_LOCKED cannot be specified without a residency "
                       "manager.";
                return E_INVALIDARG;
            }
        }

        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(heap.get(), newDescriptor);

        DebugLog(MessageId::kObjectCreated, heap.get())
            << "Created heap, Size=" << heap->GetInfo().SizeInBytes
            << ", ID3D12Pageable=" << ToHexStr(heap->mPageable.Get());

        if (ppResidencyHeapOut != nullptr) {
            *ppResidencyHeapOut = heap.release();
        }

        return S_OK;
    }

    // static
    HRESULT ResidencyHeap::CreateResidencyHeap(const RESIDENCY_HEAP_DESC& descriptor,
                                               IResidencyManager* const pResidencyManager,
                                               CreateHeapFn createHeapFn,
                                               void* pCreateHeapContext,
                                               IResidencyHeap** ppResidencyHeapOut) {
        GPGMM_RETURN_IF_NULL(pCreateHeapContext);

        // Validate residency resource heap flags must also have a residency manager.
        if (pResidencyManager == nullptr &&
            descriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Creating a heap always in budget requires a residency manager to exist.";
            return E_INVALIDARG;
        }

        if (pResidencyManager == nullptr &&
            descriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_RESIDENT) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Creating a heap always residency requires a residency manager to exist.";
            return E_INVALIDARG;
        }

        // Ensure enough budget exists before creating the heap to avoid an out-of-memory error.
        if (pResidencyManager != nullptr &&
            descriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET) {
            ResidencyManager* residencyManager = FromAPI(pResidencyManager);

            uint64_t bytesEvicted = descriptor.SizeInBytes;
            GPGMM_RETURN_IF_FAILED(residencyManager->EvictInternal(
                descriptor.SizeInBytes, descriptor.HeapSegment, &bytesEvicted));

            if (bytesEvicted < descriptor.SizeInBytes) {
                DXGI_QUERY_VIDEO_MEMORY_INFO currentVideoInfo = {};
                if (SUCCEEDED(residencyManager->QueryVideoMemoryInfo(descriptor.HeapSegment,
                                                                     &currentVideoInfo))) {
                    ErrorLog(ErrorCode::kSizeExceeded)
                        << "Unable to create heap because not enough budget exists ("
                        << GetBytesToSizeInUnits(descriptor.SizeInBytes) << " vs "
                        << GetBytesToSizeInUnits(
                               (currentVideoInfo.Budget > currentVideoInfo.CurrentUsage)
                                   ? currentVideoInfo.Budget - currentVideoInfo.CurrentUsage
                                   : 0)
                        << ") and RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET was specified.";
                }
                return E_OUTOFMEMORY;
            } else if (bytesEvicted > descriptor.SizeInBytes) {
                WarnLog(MessageId::kPerformanceWarning)
                    << "Residency manager evicted more bytes than the size of heap created  ("
                    << GetBytesToSizeInUnits(bytesEvicted) << " vs "
                    << GetBytesToSizeInUnits(descriptor.SizeInBytes)
                    << "). Evicting more memory than required may lead to excessive paging.";
            }
        }

        ComPtr<ID3D12Pageable> pageable;
        GPGMM_RETURN_IF_FAILED(createHeapFn(pCreateHeapContext, &pageable));

        return CreateResidencyHeap(descriptor, pResidencyManager, pageable.Get(),
                                   ppResidencyHeapOut);
    }

    ResidencyHeap::ResidencyHeap(ComPtr<ResidencyManager> residencyManager,
                                 ComPtr<ID3D12Pageable> pageable,
                                 const RESIDENCY_HEAP_DESC& descriptor)
        : MemoryBase(descriptor.SizeInBytes, descriptor.Alignment),
          mResidencyManager(std::move(residencyManager)),
          mPageable(std::move(pageable)),
          mHeapSegment(descriptor.HeapSegment),
          mResidencyLockCount(0),
          mState(RESIDENCY_HEAP_STATUS_UNKNOWN) {
        ASSERT(mPageable != nullptr);
        if (residencyManager != nullptr) {
            GPGMM_TRACE_EVENT_OBJECT_NEW(this);
        }
    }

    void ResidencyHeap::DeleteThis() {
        if (IsResidencyLocked() && GPGMM_UNSUCCESSFUL(Unlock())) {
            DebugLog(MessageId::kUnknown, this)
                << "Heap was locked for residency while being destroyed.";
        }

        Unknown::DeleteThis();
    }

    ResidencyHeap::~ResidencyHeap() {
        if (mResidencyManager == nullptr) {
            return;
        }

        // When a heap is destroyed, it no longer resides in resident memory, so we must evict
        // it from the residency cache. If this heap is not manually removed from the residency
        // cache, the ResidencyManager will attempt to use it after it has been deallocated.
        if (IsInList()) {
            RemoveFromList();
        }

        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
    }

    uint64_t ResidencyHeap::GetLastUsedFenceValue() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return mLastUsedFenceValue;
    }

    void ResidencyHeap::SetLastUsedFenceValue(uint64_t fenceValue) {
        std::lock_guard<std::mutex> lock(mMutex);
        mLastUsedFenceValue = fenceValue;
    }

    DXGI_MEMORY_SEGMENT_GROUP ResidencyHeap::GetMemorySegment() const {
        return mHeapSegment;
    }

    void ResidencyHeap::IncrementResidencyLockCount() {
        mResidencyLockCount.Ref();
    }

    void ResidencyHeap::DecrementResidencyLockCount() {
        mResidencyLockCount.Unref();
    }

    bool ResidencyHeap::IsResidencyLocked() const {
        return mResidencyLockCount.GetRefCount() > 0;
    }

    RESIDENCY_HEAP_INFO ResidencyHeap::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return {GetSize(), GetAlignment(), IsResidencyLocked(), mState};
    }

    HRESULT ResidencyHeap::SetDebugNameImpl(LPCWSTR name) {
        std::lock_guard<std::mutex> lock(mMutex);
        return SetDebugObjectName(mPageable.Get(), name);
    }

    HRESULT STDMETHODCALLTYPE ResidencyHeap::QueryInterface(REFIID riid, void** ppvObject) {
        return mPageable->QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResidencyHeap::AddRef() {
        return Unknown::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResidencyHeap::Release() {
        return Unknown::Release();
    }

    void ResidencyHeap::SetResidencyStatus(RESIDENCY_HEAP_STATUS newStatus) {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = newStatus;
    }

    LPCWSTR ResidencyHeap::GetDebugName() const {
        return DebugObject::GetDebugName();
    }

    HRESULT ResidencyHeap::SetDebugName(LPCWSTR Name) {
        return DebugObject::SetDebugName(Name);
    }

    HRESULT ResidencyHeap::Lock() {
        if (mResidencyManager == nullptr) {
            return S_FALSE;
        }
        return mResidencyManager->LockHeap(this);
    }

    HRESULT ResidencyHeap::Unlock() {
        if (mResidencyManager == nullptr) {
            return S_FALSE;
        }
        return mResidencyManager->UnlockHeap(this);
    }

    HRESULT ResidencyHeap::GetResidencyManager(IResidencyManager** ppResidencyManagerOut) const {
        ComPtr<IResidencyManager> residencyManager(mResidencyManager.Get());
        GPGMM_RETURN_IF_NULL(residencyManager.Get());
        if (ppResidencyManagerOut != nullptr) {
            *ppResidencyManagerOut = residencyManager.Detach();
        } else {
            return S_FALSE;
        }
        return S_OK;
    }

}  // namespace gpgmm::d3d12
