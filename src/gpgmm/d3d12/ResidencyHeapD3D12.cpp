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
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/LogD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm::d3d12 {

    // D3D12 doesn't provide a allocation info definition for non-resource heap types (eg.
    // descriptor heaps) but the info is the otherwise the same as resource heaps.
    using HEAP_ALLOCATION_INFO = D3D12_RESOURCE_ALLOCATION_INFO;

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
                                       GetDevice(committedResource.Get()));
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
        GPGMM_TRACE_EVENT_OBJECT_CALL("Heap.CreateResidencyHeap",
                                      (CREATE_HEAP_DESC{descriptor, pPageable}));

        GPGMM_RETURN_IF_NULLPTR(pPageable);

        ResidencyManager* residencyManager = static_cast<ResidencyManager*>(pResidencyManager);
        const bool isResidencyDisabled = (pResidencyManager == nullptr);

        RESIDENCY_HEAP_DESC newDescriptor = descriptor;
        const HEAP_ALLOCATION_INFO heapInfo = GetHeapAllocationInfo(pPageable);
        if (descriptor.SizeInBytes == 0) {
            newDescriptor.SizeInBytes = heapInfo.SizeInBytes;
        }

        if (newDescriptor.SizeInBytes == kInvalidSize) {
            ErrorLog(MessageId::kInvalidArgument, true) << "Heap size for residency was invalid";
            return E_INVALIDARG;
        }

        if (descriptor.Alignment == 0) {
            newDescriptor.Alignment = heapInfo.Alignment;
        }

        if (newDescriptor.Alignment == kInvalidSize) {
            ErrorLog(MessageId::kInvalidArgument, true)
                << "Heap alignment for residency was invalid.";
            return E_INVALIDARG;
        }

        std::unique_ptr<ResidencyHeap> heap(
            new ResidencyHeap(pPageable, newDescriptor, isResidencyDisabled));

        if (!isResidencyDisabled) {
            // Check if the underlying memory was implicitly made resident.
            D3D12_HEAP_FLAGS resourceHeapFlags = D3D12_HEAP_FLAG_NONE;
            if (SUCCEEDED(GetResourceHeapFlags(pPageable, &resourceHeapFlags))) {
                // Resource heaps created without the "create not resident" flag are always
                // resident.
                if (!(resourceHeapFlags & D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT)) {
                    heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_RESIDENT);
                } else {
                    heap->SetResidencyStatus(RESIDENCY_HEAP_STATUS_EVICTED);
                }
            }

            // Heap created not resident requires no budget to be created.
            if (heap->GetInfo().Status == RESIDENCY_HEAP_STATUS_EVICTED &&
                (newDescriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET)) {
                ErrorLog(heap.get(), MessageId::kInvalidArgument)
                    << "Creating a heap always in budget cannot be used with "
                       "D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT.";
                return E_INVALIDARG;
            }

            // Only heap types that are known to be created resident are eligable for evicition and
            // should be always inserted in the residency cache. For other heap types (eg.
            // descriptor heap), they must be manually locked and unlocked to be inserted into the
            // residency cache.
            if (heap->GetInfo().Status != RESIDENCY_HEAP_STATUS_UNKNOWN) {
                GPGMM_RETURN_IF_FAILED(residencyManager->InsertHeap(heap.get()),
                                       GetDevice(pPageable));
            } else {
                if (newDescriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_RESIDENT) {
                    GPGMM_RETURN_IF_FAILED(residencyManager->LockHeap(heap.get()),
                                           GetDevice(pPageable));
                    GPGMM_RETURN_IF_FAILED(residencyManager->UnlockHeap(heap.get()),
                                           GetDevice(pPageable));
                    ASSERT(heap->GetInfo().Status == RESIDENCY_HEAP_STATUS_RESIDENT);
                }
            }
        } else {
            if (newDescriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_RESIDENT) {
                WarnLog(heap.get(), MessageId::kInvalidArgument)
                    << "RESIDENCY_HEAP_FLAG_CREATE_RESIDENT was specified but had no effect "
                       "becauase residency management is not being used.";
            }
        }

        GPGMM_RETURN_IF_FAILED(heap->SetDebugName(newDescriptor.DebugName), GetDevice(pPageable));
        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(heap.get(), newDescriptor);

        DebugLog(heap.get(), MessageId::kObjectCreated)
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
        GPGMM_RETURN_IF_NULLPTR(pCreateHeapContext);

        const bool isResidencyDisabled = (pResidencyManager == nullptr);

        // Validate residency resource heap flags must also have a residency manager.
        if (isResidencyDisabled && descriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET) {
            ErrorLog(MessageId::kInvalidArgument, true)
                << "Creating a heap always in budget requires a residency manager to exist.";
            return E_INVALIDARG;
        }

        if (isResidencyDisabled && descriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_RESIDENT) {
            ErrorLog(MessageId::kInvalidArgument, true)
                << "Creating a heap always residency requires a residency manager to exist.";
            return E_INVALIDARG;
        }

        ResidencyManager* residencyManager = static_cast<ResidencyManager*>(pResidencyManager);

        // Ensure enough budget exists before creating the heap to avoid an out-of-memory error.
        if (!isResidencyDisabled && (descriptor.Flags & RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET)) {
            uint64_t bytesEvicted = descriptor.SizeInBytes;
            GPGMM_RETURN_IF_FAILED(
                residencyManager->EvictInternal(descriptor.SizeInBytes, descriptor.HeapSegment,
                                                &bytesEvicted),
                residencyManager->mDevice);

            if (bytesEvicted < descriptor.SizeInBytes) {
                DXGI_QUERY_VIDEO_MEMORY_INFO currentVideoInfo = {};
                if (SUCCEEDED(residencyManager->QueryVideoMemoryInfo(descriptor.HeapSegment,
                                                                     &currentVideoInfo))) {
                    ErrorLog(MessageId::kBudgetExceeded, true)
                        << "Unable to create heap because not enough budget exists ("
                        << GPGMM_BYTES_TO_MB(descriptor.SizeInBytes) << " vs "
                        << GPGMM_BYTES_TO_MB(
                               (currentVideoInfo.Budget > currentVideoInfo.CurrentUsage)
                                   ? currentVideoInfo.Budget - currentVideoInfo.CurrentUsage
                                   : 0)
                        << " MBs) and RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET was specified.";
                }
                return E_OUTOFMEMORY;
            }
        }

        ComPtr<ID3D12Pageable> pageable;
        GPGMM_RETURN_IF_FAILED(createHeapFn(pCreateHeapContext, &pageable),
                               GetDevice(pageable.Get()));

        return CreateResidencyHeap(descriptor, pResidencyManager, pageable.Get(),
                                   ppResidencyHeapOut);
    }

    ResidencyHeap::ResidencyHeap(ComPtr<ID3D12Pageable> pageable,
                                 const RESIDENCY_HEAP_DESC& descriptor,
                                 bool isResidencyDisabled)
        : MemoryBase(descriptor.SizeInBytes, descriptor.Alignment),
          mPageable(std::move(pageable)),
          mHeapSegment(descriptor.HeapSegment),
          mResidencyLock(0),
          mIsResidencyDisabled(isResidencyDisabled),
          mState(RESIDENCY_HEAP_STATUS_UNKNOWN) {
        ASSERT(mPageable != nullptr);
        if (!mIsResidencyDisabled) {
            GPGMM_TRACE_EVENT_OBJECT_NEW(this);
        }
    }

    ResidencyHeap::~ResidencyHeap() {
        if (mIsResidencyDisabled) {
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
        return mLastUsedFenceValue;
    }

    void ResidencyHeap::SetLastUsedFenceValue(uint64_t fenceValue) {
        mLastUsedFenceValue = fenceValue;
    }

    DXGI_MEMORY_SEGMENT_GROUP ResidencyHeap::GetHeapSegment() const {
        return mHeapSegment;
    }

    void ResidencyHeap::AddResidencyLockRef() {
        mResidencyLock.Ref();
    }

    void ResidencyHeap::ReleaseResidencyLock() {
        mResidencyLock.Unref();
    }

    bool ResidencyHeap::IsResidencyLocked() const {
        return mResidencyLock.GetRefCount() > 0;
    }

    RESIDENCY_HEAP_INFO ResidencyHeap::GetInfo() const {
        return {GetSize(), GetAlignment(), IsResidencyLocked(), mState};
    }

    HRESULT ResidencyHeap::SetDebugNameImpl(LPCWSTR name) {
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
        mState = newStatus;
    }

    LPCWSTR ResidencyHeap::GetDebugName() const {
        return DebugObject::GetDebugName();
    }

    HRESULT ResidencyHeap::SetDebugName(LPCWSTR Name) {
        return DebugObject::SetDebugName(Name);
    }

}  // namespace gpgmm::d3d12
