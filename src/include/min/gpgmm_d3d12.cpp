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

#include "gpgmm_d3d12.h"

#include <limits>

#define ReturnIfFailed(expr) \
    {                        \
        HRESULT hr = expr;   \
        if (FAILED(hr)) {    \
            return hr;       \
        }                    \
    }                        \
    for (;;)                 \
    break

namespace gpgmm::d3d12 {

    static constexpr uint64_t kInvalidOffset = std::numeric_limits<uint64_t>::max();

    // IUnknownImpl

    IUnknownImpl::IUnknownImpl() : mRefCount(1) {
    }

    IUnknownImpl::~IUnknownImpl() = default;

    HRESULT STDMETHODCALLTYPE IUnknownImpl::QueryInterface(REFIID riid, void** ppvObject) {
        // Always set out parameter to nullptr, validating it first.
        if (ppvObject == nullptr) {
            return E_INVALIDARG;
        }

        *ppvObject = nullptr;

        if (riid == IID_IUnknown) {
            // Increment reference and return pointer.
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE IUnknownImpl::AddRef() {
        return ++mRefCount;
    }

    ULONG STDMETHODCALLTYPE IUnknownImpl::Release() {
        const ULONG refCount = --mRefCount;
        if (refCount == 0) {
            DeleteThis();
        }
        return refCount;
    }

    void IUnknownImpl::DeleteThis() {
        delete this;
    }

    // Heap

    // static
    HRESULT Heap::CreateHeap(const HEAP_DESC& descriptor,
                             ResidencyManager* const pResidencyManager,
                             CreateHeapFn&& createHeapFn,
                             Heap** ppHeapOut) {
        Microsoft::WRL::ComPtr<ID3D12Pageable> pageable;
        ReturnIfFailed(createHeapFn(&pageable));

        if (ppHeapOut != nullptr) {
            *ppHeapOut = new Heap(pageable, descriptor, (pResidencyManager == nullptr));
        }

        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Heap::QueryInterface(REFIID riid, void** ppvObject) {
        return mPageable->QueryInterface(riid, ppvObject);
    }

    HEAP_INFO Heap::GetInfo() const {
        return {};
    }

    Heap::Heap(Microsoft::WRL::ComPtr<ID3D12Pageable> pageable,
               const HEAP_DESC& descriptor,
               bool isResidencyDisabled)
        : MemoryBase(descriptor.SizeInBytes, descriptor.Alignment), mPageable(std::move(pageable)) {
    }

    // ResidencyList

    ResidencyList::ResidencyList() = default;

    HRESULT ResidencyList::Add(Heap* pHeap) {
        return S_OK;
    }

    HRESULT ResidencyList::Reset() {
        return S_OK;
    }

    // ResidencyManager

    // static
    HRESULT ResidencyManager::CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                                     ResidencyManager** ppResidencyManagerOut) {
        if (ppResidencyManagerOut != nullptr) {
            *ppResidencyManagerOut = new ResidencyManager(descriptor);
        }

        return S_OK;
    }

    ResidencyManager::~ResidencyManager() = default;

    HRESULT ResidencyManager::LockHeap(Heap* pHeap) {
        return S_OK;
    }

    HRESULT ResidencyManager::UnlockHeap(Heap* pHeap) {
        return S_OK;
    }

    HRESULT ResidencyManager::ExecuteCommandLists(ID3D12CommandQueue* pQueue,
                                                  ID3D12CommandList* const* ppCommandLists,
                                                  ResidencyList* const* ppResidencyLists,
                                                  uint32_t count) {
        pQueue->ExecuteCommandLists(count, ppCommandLists);
        return S_OK;
    }

    HRESULT ResidencyManager::SetVideoMemoryReservation(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
        uint64_t availableForReservation,
        uint64_t* pCurrentReservationOut) {
        return S_OK;
    }

    HRESULT ResidencyManager::QueryVideoMemoryInfo(
        const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup,
        DXGI_QUERY_VIDEO_MEMORY_INFO* pVideoMemoryInfoOut) {
        return S_OK;
    }

    RESIDENCY_INFO ResidencyManager::GetInfo() const {
        return {0, 0};
    }

    ResidencyManager::ResidencyManager(const RESIDENCY_DESC& descriptor)
        : mDevice(std::move(descriptor.Device)), mAdapter(std::move(descriptor.Adapter)) {
    }

    // ResourceAllocation

    void ResourceAllocation::DeleteThis() {
        GetAllocator()->DeallocateMemory(std::unique_ptr<ResourceAllocation>(this));
    }

    HRESULT ResourceAllocation::Map(uint32_t subresource,
                                    const D3D12_RANGE* pReadRange,
                                    void** ppDataOut) {
        return mResource->Map(subresource, pReadRange, ppDataOut);
    }

    void ResourceAllocation::Unmap(uint32_t subresource, const D3D12_RANGE* pWrittenRange) {
        return mResource->Unmap(subresource, pWrittenRange);
    }

    ID3D12Resource* ResourceAllocation::GetResource() const {
        return mResource.Get();
    }

    D3D12_GPU_VIRTUAL_ADDRESS ResourceAllocation::GetGPUVirtualAddress() const {
        return mResource->GetGPUVirtualAddress();
    }

    uint64_t ResourceAllocation::GetOffsetFromResource() const {
        return 0;
    }

    RESOURCE_ALLOCATION_INFO ResourceAllocation::GetInfo() const {
        return {GetSize(), GetAlignment()};
    }

    Heap* ResourceAllocation::GetMemory() const {
        return static_cast<Heap*>(MemoryAllocation::GetMemory());
    }

    ResourceAllocation::ResourceAllocation(const RESOURCE_ALLOCATION_DESC& desc,
                                           MemoryAllocator* allocator,
                                           Heap* resourceHeap,
                                           Microsoft::WRL::ComPtr<ID3D12Resource> resource)
        : MemoryAllocation(allocator, resourceHeap, desc.SizeInBytes),
          mResource(std::move(resource)) {
    }

    // ResourceAllocator

    // static
    HRESULT ResourceAllocator::CreateAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                               ResourceAllocator** ppResourceAllocatorOut,
                                               ResidencyManager** ppResidencyManagerOut) {
        if (allocatorDescriptor.Device == nullptr || allocatorDescriptor.Adapter == nullptr) {
            return E_INVALIDARG;
        }

        Microsoft::WRL::ComPtr<ResidencyManager> residencyManager;
        if (ppResidencyManagerOut != nullptr) {
            RESIDENCY_DESC residencyDesc = {};
            residencyDesc.Device = allocatorDescriptor.Device;

            D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
            ReturnIfFailed(residencyDesc.Device->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE,
                                                                     &arch, sizeof(arch)));
            residencyDesc.IsUMA = arch.UMA;

            ReturnIfFailed(allocatorDescriptor.Adapter.As(&residencyDesc.Adapter));

            ReturnIfFailed(
                ResidencyManager::CreateResidencyManager(residencyDesc, &residencyManager));
        }

        Microsoft::WRL::ComPtr<ResourceAllocator> resourceAllocator;
        ReturnIfFailed(
            CreateAllocator(allocatorDescriptor, residencyManager.Get(), &resourceAllocator));

        if (ppResourceAllocatorOut != nullptr) {
            *ppResourceAllocatorOut = resourceAllocator.Detach();
        }

        if (ppResidencyManagerOut != nullptr) {
            *ppResidencyManagerOut = residencyManager.Detach();
        }

        return S_OK;
    }

    // static
    HRESULT ResourceAllocator::CreateAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                               ResidencyManager* pResidencyManager,
                                               ResourceAllocator** ppResourceAllocatorOut) {
        if (ppResourceAllocatorOut != nullptr) {
            *ppResourceAllocatorOut = new ResourceAllocator(allocatorDescriptor, pResidencyManager);
        }

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                              const D3D12_RESOURCE_DESC& resourceDescriptor,
                                              D3D12_RESOURCE_STATES initialResourceState,
                                              const D3D12_CLEAR_VALUE* pClearValue,
                                              ResourceAllocation** ppResourceAllocationOut) {
        Heap* resourceHeap = nullptr;
        Microsoft::WRL::ComPtr<ID3D12Resource> committedResource;

        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            mDevice->GetResourceAllocationInfo(0, 1, &resourceDescriptor);

        HEAP_DESC resourceHeapDesc = {};
        resourceHeapDesc.SizeInBytes = resourceInfo.SizeInBytes;
        resourceHeapDesc.Alignment = resourceInfo.Alignment;

        ReturnIfFailed(Heap::CreateHeap(
            resourceHeapDesc, mResidencyManager.Get(),
            [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
                D3D12_HEAP_PROPERTIES heapProperties = {};
                heapProperties.Type = allocationDescriptor.HeapType;

                ReturnIfFailed(mDevice->CreateCommittedResource(
                    &heapProperties, D3D12_HEAP_FLAG_NONE, &resourceDescriptor,
                    initialResourceState, pClearValue, IID_PPV_ARGS(&committedResource)));

                Microsoft::WRL::ComPtr<ID3D12Pageable> pageable;
                ReturnIfFailed(committedResource.As(&pageable));
                *ppPageableOut = pageable.Detach();
                return S_OK;
            },
            &resourceHeap));

        const uint64_t& allocationSize = resourceHeap->GetSize();
        mInfo.UsedMemoryUsage += allocationSize;
        mInfo.UsedMemoryCount++;
        mInfo.UsedBlockUsage += allocationSize;

        RESOURCE_ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapOffset = kInvalidOffset;
        allocationDesc.SizeInBytes = resourceInfo.SizeInBytes;
        allocationDesc.Method = AllocationMethod::kStandalone;

        *ppResourceAllocationOut = new ResourceAllocation(allocationDesc, this, resourceHeap,
                                                          std::move(committedResource));

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResource(
        Microsoft::WRL::ComPtr<ID3D12Resource> committedResource,
        ResourceAllocation** ppResourceAllocationOut) {
        return E_NOTIMPL;
    }

    uint64_t ResourceAllocator::ReleaseMemory(uint64_t bytesToRelease) {
        return 0;
    }

    RESOURCE_ALLOCATOR_INFO ResourceAllocator::GetInfo() const {
        return mInfo;
    }

    HRESULT ResourceAllocator::CheckFeatureSupport(ALLOCATOR_FEATURE feature,
                                                   void* pFeatureSupportData,
                                                   uint32_t featureSupportDataSize) const {
        return E_INVALIDARG;  // Unsupported
    }

    ResourceAllocator::ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                                         Microsoft::WRL::ComPtr<ResidencyManager> residencyManager)
        : mDevice(std::move(descriptor.Device)), mResidencyManager(std::move(residencyManager)) {
    }

    void ResourceAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        const uint64_t& allocationSize = allocation->GetSize();
        mInfo.UsedMemoryUsage -= allocationSize;
        mInfo.UsedMemoryCount--;
        mInfo.UsedBlockUsage -= allocationSize;
        delete allocation->GetMemory();
    }

}  // namespace gpgmm::d3d12
