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
#include "gpgmm/d3d12/LogD3D12.h"
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
                GPGMM_RETURN_IF_FAILED(committedResource->GetHeapProperties(nullptr, heapFlags));
                return S_OK;
            }

            return E_INVALIDARG;
        }

        D3D12_RESOURCE_ALLOCATION_INFO GetResourceHeapInfo(ComPtr<ID3D12Pageable> pageable) {
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

        HEAP_ALLOCATION_INFO GetDescriptorHeapInfo(ComPtr<ID3D12Pageable> pageable) {
            ComPtr<ID3D12DescriptorHeap> heap;
            if (SUCCEEDED(pageable.As(&heap))) {
                const D3D12_DESCRIPTOR_HEAP_DESC desc = heap->GetDesc();
                const uint64_t sizePerDescriptor =
                    GetDevice(heap.Get())->GetDescriptorHandleIncrementSize(desc.Type);
                return {desc.NumDescriptors * sizePerDescriptor, sizePerDescriptor};
            }

            return {kInvalidSize, kInvalidSize};
        }

        HEAP_ALLOCATION_INFO GetHeapInfo(ComPtr<ID3D12Pageable> pageable) {
            const D3D12_RESOURCE_ALLOCATION_INFO resourceHeapInfo = GetResourceHeapInfo(pageable);
            if (resourceHeapInfo.SizeInBytes != kInvalidSize) {
                return resourceHeapInfo;
            }

            const HEAP_ALLOCATION_INFO descriptorHeapInfo = GetDescriptorHeapInfo(pageable);
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
        GPGMM_RETURN_IF_NULLPTR(pCreateHeapContext);

        const bool isResidencyDisabled = (pResidencyManager == nullptr);

        HEAP_DESC newDescriptor = descriptor;

        if (isResidencyDisabled && (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET)) {
            WarningLog(MessageId::kInvalidArgument, true)
                << "HEAP_FLAG_ALWAYS_IN_BUDGET was specified but ignored since no residency "
                   "manager was specified.";
            newDescriptor.Flags &= ~(HEAP_FLAG_ALWAYS_IN_BUDGET);
        }

        // Ensure enough budget exists before creating the heap to avoid an out-of-memory error.
        ResidencyManager* residencyManager = static_cast<ResidencyManager*>(pResidencyManager);
        if (newDescriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET) {
            uint64_t bytesEvicted = newDescriptor.SizeInBytes;
            GPGMM_RETURN_IF_FAILED(residencyManager->EvictInternal(
                newDescriptor.SizeInBytes, newDescriptor.HeapSegment, &bytesEvicted));

            if (bytesEvicted < descriptor.SizeInBytes) {
                DXGI_QUERY_VIDEO_MEMORY_INFO currentVideoInfo = {};
                if (SUCCEEDED(residencyManager->QueryVideoMemoryInfo(descriptor.HeapSegment,
                                                                     &currentVideoInfo))) {
                    ErrorLog(MessageId::kBudgetExceeded, true)
                        << "Unable to create heap because not enough budget exists ("
                        << GPGMM_BYTES_TO_MB(newDescriptor.SizeInBytes) << " vs "
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
        GPGMM_RETURN_IF_FAILED_ON_DEVICE(createHeapFn(pCreateHeapContext, &pageable),
                                         GetDevice(pageable.Get()));

        // Pageable-based type is required for residency-managed heaps.
        GPGMM_RETURN_IF_NULLPTR(pageable);

        const HEAP_ALLOCATION_INFO heapInfo = GetHeapInfo(pageable);

        if (descriptor.SizeInBytes == 0) {
            newDescriptor.SizeInBytes = heapInfo.SizeInBytes;
        }

        if (newDescriptor.SizeInBytes == kInvalidSize ||
            heapInfo.SizeInBytes != newDescriptor.SizeInBytes) {
            ErrorLog(MessageId::kInvalidArgument, true)
                << "Heap size was determined to be incorrect: " << descriptor.SizeInBytes
                << " bytes.";
            return E_INVALIDARG;
        }

        if ((descriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET) &&
            (descriptor.SizeInBytes != newDescriptor.SizeInBytes)) {
            ErrorLog(MessageId::kInvalidArgument, true)
                << "HEAP_FLAG_ALWAYS_IN_BUDGET was specified but the heap size was determined to "
                   "be incorrect: "
                << descriptor.SizeInBytes << " vs " << newDescriptor.SizeInBytes << " bytes.";
            return E_INVALIDARG;
        }

        if (descriptor.Alignment == 0) {
            newDescriptor.Alignment = heapInfo.Alignment;
        }

        if (newDescriptor.Alignment == kInvalidSize ||
            heapInfo.Alignment != newDescriptor.Alignment) {
            ErrorLog(MessageId::kInvalidArgument, true)
                << "Heap alignment was determined to be incorrect: " << descriptor.Alignment
                << " bytes.";
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
                (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_BUDGET)) {
                ErrorLog(heap.get(), MessageId::kInvalidArgument)
                    << "Creating a heap always in budget cannot be used with "
                       "D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT.";
                return E_INVALIDARG;
            }

            // Only heap types that are known to be created resident are eligable for evicition and
            // should be always inserted in the residency cache. For other heap types (eg.
            // descriptor heap), they must be manually locked and unlocked to be inserted into the
            // residency cache.
            if (heap->mState != RESIDENCY_STATUS_UNKNOWN) {
                GPGMM_RETURN_IF_FAILED(residencyManager->InsertHeap(heap.get()));
            } else {
                if (newDescriptor.Flags & HEAP_FLAG_ALWAYS_IN_RESIDENCY) {
                    GPGMM_RETURN_IF_FAILED(residencyManager->LockHeap(heap.get()));
                    GPGMM_RETURN_IF_FAILED(residencyManager->UnlockHeap(heap.get()));
                    ASSERT(heap->mState == RESIDENCY_STATUS_CURRENT_RESIDENT);
                }
            }
        } else {
            if (descriptor.Flags & HEAP_FLAG_ALWAYS_IN_RESIDENCY) {
                WarningLog(heap.get(), MessageId::kInvalidArgument)
                    << "HEAP_FLAG_ALWAYS_IN_RESIDENCY was specified but had no effect becauase "
                       "residency management is "
                       "not being used.";
            }
        }

        GPGMM_RETURN_IF_FAILED(heap->SetDebugName(newDescriptor.DebugName));
        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(heap.get(), newDescriptor);

        DebugLog(heap.get(), MessageId::kObjectCreated)
            << "Created heap, Size=" << heap->GetInfo().SizeInBytes
            << ", ID3D12Pageable=" << ToHexStr(heap->mPageable.Get());

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
          mHeapSegment(descriptor.HeapSegment),
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
        return "IHeap";
    }

    uint64_t Heap::GetLastUsedFenceValue() const {
        return mLastUsedFenceValue;
    }

    void Heap::SetLastUsedFenceValue(uint64_t fenceValue) {
        mLastUsedFenceValue = fenceValue;
    }

    DXGI_MEMORY_SEGMENT_GROUP Heap::GetHeapSegment() const {
        return mHeapSegment;
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
