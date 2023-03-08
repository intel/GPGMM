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

#include "gpgmm/d3d12/HeapD3D12.h"

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/Math.h"

namespace gpgmm::d3d12 {

    using HEAP_ALLOCATION_INFO = D3D12_RESOURCE_ALLOCATION_INFO;

    namespace {

        // Returns the resource heap flags or E_INVALIDARG, when the memory type doesn't allow
        // resources.
        HRESULT GetResourceHeapFlags(ComPtr<ID3D12Pageable> pageable, D3D12_HEAP_FLAGS* heapFlags) {
            ComPtr<ID3D12Heap> heap;
            if (SUCCEEDED(pageable.As(&heap))) {
                if (heapFlags != nullptr) {
                    *heapFlags = heap->GetDesc().Flags;
                }
                return S_OK;
            }

            ComPtr<ID3D12Resource> committedResource;
            if (SUCCEEDED(pageable.As(&committedResource))) {
                ReturnIfFailed(committedResource->GetHeapProperties(nullptr, heapFlags));
                return S_OK;
            }

            return E_INVALIDARG;
        }

        D3D12_RESOURCE_ALLOCATION_INFO GetResourceHeapInfo(ID3D12Device* device,
                                                           ComPtr<ID3D12Pageable> pageable) {
            ComPtr<ID3D12Heap> heap;
            if (SUCCEEDED(pageable.As(&heap))) {
                const D3D12_HEAP_DESC desc = heap->GetDesc();
                return {desc.SizeInBytes, desc.Alignment};
            }

            ComPtr<ID3D12Resource> committedResource;
            if (SUCCEEDED(pageable.As(&committedResource))) {
                const D3D12_RESOURCE_DESC desc = committedResource->GetDesc();
                const D3D12_RESOURCE_ALLOCATION_INFO info =
                    device->GetResourceAllocationInfo(0, 1, &desc);
                return info;
            }

            return {kInvalidSize, kInvalidSize};
        }

        HEAP_ALLOCATION_INFO GetDescriptorHeapInfo(ID3D12Device* device,
                                                   ComPtr<ID3D12Pageable> pageable) {
            ComPtr<ID3D12DescriptorHeap> heap;
            if (SUCCEEDED(pageable.As(&heap))) {
                const D3D12_DESCRIPTOR_HEAP_DESC desc = heap->GetDesc();
                const uint64_t sizePerDescriptor =
                    device->GetDescriptorHandleIncrementSize(desc.Type);
                return {desc.NumDescriptors * sizePerDescriptor, sizePerDescriptor};
            }

            return {kInvalidSize, kInvalidSize};
        }

        HEAP_ALLOCATION_INFO GetHeapInfo(ID3D12Device* device, ComPtr<ID3D12Pageable> pageable) {
            const D3D12_RESOURCE_ALLOCATION_INFO resourceHeapInfo =
                GetResourceHeapInfo(device, pageable);
            if (resourceHeapInfo.SizeInBytes != kInvalidSize) {
                return resourceHeapInfo;
            }

            const HEAP_ALLOCATION_INFO descriptorHeapInfo = GetDescriptorHeapInfo(device, pageable);
            if (descriptorHeapInfo.SizeInBytes != kInvalidSize) {
                return descriptorHeapInfo;
            }

            return {kInvalidSize, kInvalidSize};
        }

    }  // namespace

    HEAP_FLAGS GetHeapFlags(D3D12_HEAP_FLAGS heapFlags, bool alwaysCreatedInBudget) {
        if (alwaysCreatedInBudget) {
            return HEAP_FLAG_ALWAYS_IN_BUDGET | HEAP_FLAG_ALWAYS_IN_RESIDENCY;
        }

        return HEAP_FLAG_ALWAYS_IN_RESIDENCY;
    }

    HRESULT CreateHeap(const HEAP_DESC& descriptor,
                       IResidencyManager* const pResidencyManager,
                       CreateHeapFn createHeapFn,
                       void* pCreateHeapContext,
                       IHeap** ppHeapOut) {
        return Heap::CreateHeap(descriptor, pResidencyManager, createHeapFn, pCreateHeapContext,
                                ppHeapOut);
    }

    // static
    HRESULT Heap::CreateHeap(const HEAP_DESC& descriptor,
                             IResidencyManager* const pResidencyManager,
                             CreateHeapFn createHeapFn,
                             void* pCreateHeapContext,
                             IHeap** ppHeapOut) {
        const bool isResidencyDisabled = (pResidencyManager == nullptr);

        ResidencyManager* residencyManager = static_cast<ResidencyManager*>(pResidencyManager);

        // Ensure enough budget exists before creating the heap to avoid an out-of-memory error.
        if (!isResidencyDisabled && (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET)) {
            if (FAILED(residencyManager->EnsureInBudget(descriptor.SizeInBytes,
                                                        descriptor.MemorySegmentGroup))) {
                DXGI_QUERY_VIDEO_MEMORY_INFO currentVideoInfo = {};
                if (SUCCEEDED(residencyManager->QueryVideoMemoryInfo(descriptor.MemorySegmentGroup,
                                                                     &currentVideoInfo))) {
                    gpgmm::ErrorLog(MessageId::kBudgetExceeded)
                        << "Unable to create heap because not enough budget exists ("
                        << GPGMM_BYTES_TO_MB(descriptor.SizeInBytes) << " vs "
                        << GPGMM_BYTES_TO_MB(
                               (currentVideoInfo.Budget > currentVideoInfo.CurrentUsage)
                                   ? currentVideoInfo.Budget - currentVideoInfo.CurrentUsage
                                   : 0)
                        << " MBs) and HEAP_FLAG_ALWAYS_IN_BUDGET was specified.";
                }

                return E_OUTOFMEMORY;
            }
        }

        ComPtr<ID3D12Pageable> pageable;
        ReturnIfFailed(createHeapFn(pCreateHeapContext, &pageable));

        // Pageable-based type is required for residency-managed heaps.
        ReturnIfNullptr(pageable);

        HEAP_DESC newDescriptor = descriptor;

        ComPtr<ID3D12Device> device;
        ReturnIfFailed(pageable->GetDevice(IID_PPV_ARGS(&device)));

        const HEAP_ALLOCATION_INFO heapInfo = GetHeapInfo(device.Get(), pageable);
        if (heapInfo.SizeInBytes != kInvalidSize &&
            descriptor.SizeInBytes != heapInfo.SizeInBytes) {
            newDescriptor.SizeInBytes = heapInfo.SizeInBytes;
        }

        if (descriptor.SizeInBytes != 0 && descriptor.SizeInBytes != newDescriptor.SizeInBytes) {
            gpgmm::WarningLog(MessageId::kInvalidArgument)
                << "Heap size was specified but ignored because it was determined to be incorrect: "
                << GPGMM_BYTES_TO_MB(descriptor.SizeInBytes) << " vs "
                << GPGMM_BYTES_TO_MB(newDescriptor.SizeInBytes) << " MBs.";
        }

        if (heapInfo.Alignment != kInvalidSize && descriptor.Alignment != heapInfo.Alignment) {
            newDescriptor.Alignment = heapInfo.Alignment;
        }

        if (descriptor.Alignment != 0 && descriptor.Alignment != newDescriptor.Alignment) {
            gpgmm::WarningLog(MessageId::kInvalidArgument)
                << "Heap alignment was specified but ignored because it was determined to be "
                   "incorrect: "
                << descriptor.Alignment << " vs " << newDescriptor.Alignment << " bytes.";
        }

        if (newDescriptor.Alignment == kInvalidSize) {
            gpgmm::ErrorLog(MessageId::kInvalidArgument)
                << "Heap alignment could not be determined and must be specified by "
                   "HEAP_DESC::SizeInBytes.";
            return E_INVALIDARG;
        }

        if (newDescriptor.SizeInBytes == kInvalidSize) {
            gpgmm::ErrorLog(MessageId::kInvalidArgument)
                << "Heap size could not be determined and must be specified by "
                   "HEAP_DESC::Alignment.";
            return E_INVALIDARG;
        }

        GPGMM_TRACE_EVENT_OBJECT_CALL("Heap.CreateHeap",
                                      (CREATE_HEAP_DESC{newDescriptor, pageable.Get()}));

        std::unique_ptr<Heap> heap(new Heap(pageable, newDescriptor, isResidencyDisabled));

        if (!isResidencyDisabled) {
            // Check if the underlying memory was implicitly made resident.
            D3D12_HEAP_FLAGS resourceHeapFlags = D3D12_HEAP_FLAG_NONE;
            if (SUCCEEDED(GetResourceHeapFlags(pageable, &resourceHeapFlags))) {
                // Resource heaps created without the "create not resident" flag are always
                // resident.
                if (!(resourceHeapFlags & D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT)) {
                    heap->mState = RESIDENCY_STATUS_CURRENT_RESIDENT;
                } else {
                    heap->mState = RESIDENCY_STATUS_PENDING_RESIDENCY;
                }
            }

            // Heap created not resident requires no budget to be created.
            if (heap->mState == RESIDENCY_STATUS_PENDING_RESIDENCY &&
                (newDescriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET)) {
                gpgmm::ErrorLog(MessageId::kInvalidArgument)
                    << "Creating a heap always in budget cannot be used with "
                       "D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT.";
                return E_INVALIDARG;
            }

            // Only heap types that are known to be created resident are eligable for evicition and
            // should be always inserted in the residency cache. For other heap types (eg.
            // descriptor heap), they must be manually locked and unlocked to be inserted into the
            // residency cache.
            if (heap->mState != RESIDENCY_STATUS_UNKNOWN) {
                ReturnIfFailed(residencyManager->InsertHeap(heap.get()));
            } else {
                if (newDescriptor.Flags & HEAP_FLAG_ALWAYS_IN_RESIDENCY) {
                    ReturnIfFailed(residencyManager->LockHeap(heap.get()));
                    ReturnIfFailed(residencyManager->UnlockHeap(heap.get()));
                    ASSERT(heap->mState == RESIDENCY_STATUS_CURRENT_RESIDENT);
                }
            }
        } else {
            if (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_RESIDENCY) {
                gpgmm::WarningLog(MessageId::kInvalidArgument)
                    << "HEAP_FLAG_ALWAYS_IN_RESIDENCY was specified but had no effect becauase "
                       "residency management is "
                       "not being used.";
            }
        }

        ReturnIfFailed(heap->SetDebugName(newDescriptor.DebugName));
        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(heap.get(), newDescriptor);

        if (ppHeapOut != nullptr) {
            *ppHeapOut = heap.release();
        }

        return S_OK;
    }

    Heap::Heap(ComPtr<ID3D12Pageable> pageable,
               const HEAP_DESC& descriptor,
               bool isResidencyDisabled)
        : MemoryBase(descriptor.SizeInBytes, descriptor.Alignment),
          mPageable(std::move(pageable)),
          mMemorySegmentGroup(descriptor.MemorySegmentGroup),
          mResidencyLock(0),
          mIsResidencyDisabled(isResidencyDisabled),
          mState(RESIDENCY_STATUS_UNKNOWN) {
        ASSERT(mPageable != nullptr);
        if (!mIsResidencyDisabled) {
            GPGMM_TRACE_EVENT_OBJECT_NEW(this);
        }
    }

    Heap::~Heap() {
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

    const char* Heap::GetTypename() const {
        return "Heap";
    }

    uint64_t Heap::GetLastUsedFenceValue() const {
        return mLastUsedFenceValue;
    }

    void Heap::SetLastUsedFenceValue(uint64_t fenceValue) {
        mLastUsedFenceValue = fenceValue;
    }

    DXGI_MEMORY_SEGMENT_GROUP Heap::GetMemorySegmentGroup() const {
        return mMemorySegmentGroup;
    }

    void Heap::AddResidencyLockRef() {
        mResidencyLock.Ref();
    }

    void Heap::ReleaseResidencyLock() {
        mResidencyLock.Unref();
    }

    bool Heap::IsResidencyLocked() const {
        return mResidencyLock.GetRefCount() > 0;
    }

    HEAP_INFO Heap::GetInfo() const {
        return {GetSize(), GetAlignment(), IsResidencyLocked(), IsInList(), mState};
    }

    HRESULT Heap::SetDebugNameImpl(LPCWSTR name) {
        return SetDebugObjectName(mPageable.Get(), name);
    }

    HRESULT STDMETHODCALLTYPE Heap::QueryInterface(REFIID riid, void** ppvObject) {
        return mPageable->QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE Heap::AddRef() {
        return Unknown::AddRef();
    }

    ULONG STDMETHODCALLTYPE Heap::Release() {
        return Unknown::Release();
    }

    void Heap::SetResidencyState(RESIDENCY_STATUS newStatus) {
        mState = newStatus;
    }

    LPCWSTR Heap::GetDebugName() const {
        return DebugObject::GetDebugName();
    }

    HRESULT Heap::SetDebugName(LPCWSTR Name) {
        return DebugObject::SetDebugName(Name);
    }

}  // namespace gpgmm::d3d12
