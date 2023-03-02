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

    // Unknown

    Unknown::Unknown() : mRefCount(1) {
    }

    Unknown::~Unknown() = default;

    HRESULT STDMETHODCALLTYPE Unknown::QueryInterface(REFIID riid, void** ppvObject) {
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

    ULONG STDMETHODCALLTYPE Unknown::AddRef() {
        return ++mRefCount;
    }

    ULONG STDMETHODCALLTYPE Unknown::Release() {
        const ULONG refCount = --mRefCount;
        if (refCount == 0) {
            DeleteThis();
        }
        return refCount;
    }

    void Unknown::DeleteThis() {
        delete this;
    }

    // Heap

    // static
    HRESULT Heap::CreateHeap(const HEAP_DESC& descriptor,
                             IResidencyManager* const pResidencyManager,
                             CreateHeapFn createHeapFn,
                             void* context,
                             IHeap** ppHeapOut) {
        Microsoft::WRL::ComPtr<ID3D12Pageable> pageable;
        ReturnIfFailed(createHeapFn(context, &pageable));

        if (ppHeapOut != nullptr) {
            *ppHeapOut = new Heap(pageable, descriptor, (pResidencyManager == nullptr));
        }

        return S_OK;
    }

    Heap::Heap(Microsoft::WRL::ComPtr<ID3D12Pageable> pageable,
               const HEAP_DESC& descriptor,
               bool isResidencyDisabled)
        : MemoryBase(descriptor.SizeInBytes, descriptor.Alignment), mPageable(std::move(pageable)) {
    }

    HEAP_INFO Heap::GetInfo() const {
        return {GetSize(), GetAlignment(), false, false, RESIDENCY_STATUS_UNKNOWN};
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

    LPCWSTR Heap::GetDebugName() const {
        return nullptr;
    }

    HRESULT Heap::SetDebugName(LPCWSTR Name) {
        return E_NOTIMPL;
    }

    // ResidencyList

    HRESULT CreateResidencyList(IResidencyList** ppResidencyListOut) {
        if (ppResidencyListOut != nullptr) {
            *ppResidencyListOut = new ResidencyList();
        }
        return S_OK;
    }

    ResidencyList::ResidencyList() = default;

    HRESULT ResidencyList::Add(IHeap* pHeap) {
        return S_OK;
    }

    HRESULT ResidencyList::Reset() {
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ResidencyList::QueryInterface(REFIID riid, void** ppvObject) {
        return Unknown::QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResidencyList::AddRef() {
        return Unknown::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResidencyList::Release() {
        return Unknown::Release();
    }

    // ResidencyManager

    HRESULT CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                   IResidencyManager** ppResidencyManagerOut) {
        return ResidencyManager::CreateResidencyManager(descriptor, ppResidencyManagerOut);
    }

    // static
    HRESULT ResidencyManager::CreateResidencyManager(const RESIDENCY_DESC& descriptor,
                                                     IResidencyManager** ppResidencyManagerOut) {
        if (ppResidencyManagerOut != nullptr) {
            *ppResidencyManagerOut = new ResidencyManager(descriptor);
        }

        return S_OK;
    }

    ResidencyManager::~ResidencyManager() = default;

    HRESULT ResidencyManager::LockHeap(IHeap* pHeap) {
        return S_OK;
    }

    HRESULT ResidencyManager::UnlockHeap(IHeap* pHeap) {
        return S_OK;
    }

    HRESULT ResidencyManager::ExecuteCommandLists(ID3D12CommandQueue* pQueue,
                                                  ID3D12CommandList* const* ppCommandLists,
                                                  IResidencyList* const* ppResidencyLists,
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

    HRESULT ResidencyManager::SetResidencyState(IHeap* pHeap, const RESIDENCY_STATUS& state) {
        return S_OK;
    }

    HRESULT ResidencyManager::QueryStats(RESIDENCY_MANAGER_STATS* pResidencyManagerStats) {
        return E_NOTIMPL;
    }

    ResidencyManager::ResidencyManager(const RESIDENCY_DESC& descriptor)
        : mDevice(std::move(descriptor.Device)), mAdapter(std::move(descriptor.Adapter)) {
    }

    HRESULT STDMETHODCALLTYPE ResidencyManager::QueryInterface(REFIID riid, void** ppvObject) {
        return Unknown::QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResidencyManager::AddRef() {
        return Unknown::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResidencyManager::Release() {
        return Unknown::Release();
    }

    LPCWSTR ResidencyManager::GetDebugName() const {
        return L"";
    }

    HRESULT ResidencyManager::SetDebugName(LPCWSTR Name) {
        return S_OK;
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

    IHeap* ResourceAllocation::GetMemory() const {
        return static_cast<Heap*>(MemoryAllocation::GetMemory());
    }

    ResourceAllocation::ResourceAllocation(MemoryAllocator* allocator,
                                           Heap* resourceHeap,
                                           Microsoft::WRL::ComPtr<ID3D12Resource> resource)
        : MemoryAllocation(allocator, resourceHeap), mResource(std::move(resource)) {
    }

    HRESULT STDMETHODCALLTYPE ResourceAllocation::QueryInterface(REFIID riid, void** ppvObject) {
        return Unknown::QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResourceAllocation::AddRef() {
        return Unknown::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResourceAllocation::Release() {
        return Unknown::Release();
    }

    LPCWSTR ResourceAllocation::GetDebugName() const {
        return nullptr;
    }

    HRESULT ResourceAllocation::SetDebugName(LPCWSTR Name) {
        return E_NOTIMPL;
    }

    // ResourceAllocator

    HRESULT CreateResourceAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                    IResourceAllocator** ppResourceAllocatorOut,
                                    IResidencyManager** ppResidencyManagerOut) {
        return ResourceAllocator::CreateResourceAllocator(
            allocatorDescriptor, ppResourceAllocatorOut, ppResidencyManagerOut);
    }

    // static
    HRESULT ResourceAllocator::CreateResourceAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                                       IResourceAllocator** ppResourceAllocatorOut,
                                                       IResidencyManager** ppResidencyManagerOut) {
        if (allocatorDescriptor.Device == nullptr) {
            return E_INVALIDARG;
        }

        Microsoft::WRL::ComPtr<IResidencyManager> residencyManager;
        if (ppResidencyManagerOut != nullptr) {
            RESIDENCY_DESC residencyDesc = {};
            residencyDesc.Device = allocatorDescriptor.Device;

            if (allocatorDescriptor.Adapter != nullptr) {
                ReturnIfFailed(allocatorDescriptor.Adapter->QueryInterface(
                    IID_PPV_ARGS(&residencyDesc.Adapter)));
            }

            ReturnIfFailed(
                ResidencyManager::CreateResidencyManager(residencyDesc, &residencyManager));
        }

        Microsoft::WRL::ComPtr<IResourceAllocator> resourceAllocator;
        ReturnIfFailed(CreateResourceAllocator(allocatorDescriptor, residencyManager.Get(),
                                               &resourceAllocator));

        if (ppResourceAllocatorOut != nullptr) {
            *ppResourceAllocatorOut = resourceAllocator.Detach();
        }

        if (ppResidencyManagerOut != nullptr) {
            *ppResidencyManagerOut = residencyManager.Detach();
        }

        return S_OK;
    }

    // static
    HRESULT ResourceAllocator::CreateResourceAllocator(
        const ALLOCATOR_DESC& allocatorDescriptor,
        IResidencyManager* pResidencyManager,
        IResourceAllocator** ppResourceAllocatorOut) {
        if (ppResourceAllocatorOut != nullptr) {
            *ppResourceAllocatorOut = new ResourceAllocator(
                allocatorDescriptor, static_cast<ResidencyManager*>(pResidencyManager));
        }

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                              const D3D12_RESOURCE_DESC& resourceDescriptor,
                                              D3D12_RESOURCE_STATES initialResourceState,
                                              const D3D12_CLEAR_VALUE* pClearValue,
                                              IResourceAllocation** ppResourceAllocationOut) {
        IHeap* resourceHeap = nullptr;
        Microsoft::WRL::ComPtr<ID3D12Resource> committedResource;

        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            mDevice->GetResourceAllocationInfo(0, 1, &resourceDescriptor);

        HEAP_DESC resourceHeapDesc = {};
        resourceHeapDesc.SizeInBytes = resourceInfo.SizeInBytes;
        resourceHeapDesc.Alignment = resourceInfo.Alignment;

        CreateCommittedResourceCallbackContext callbackContext(
            mDevice.Get(), allocationDescriptor, committedResource, &resourceDescriptor,
            pClearValue, initialResourceState);

        ReturnIfFailed(Heap::CreateHeap(resourceHeapDesc, mResidencyManager.Get(),
                                        CreateCommittedResourceCallbackContext::CreateHeap,
                                        &callbackContext, &resourceHeap));

        const uint64_t allocationSize = resourceHeapDesc.SizeInBytes;
        mStats.UsedMemoryUsage += allocationSize;
        mStats.UsedMemoryCount++;
        mStats.UsedBlockUsage += allocationSize;

        *ppResourceAllocationOut = new ResourceAllocation(this, static_cast<Heap*>(resourceHeap),
                                                          std::move(committedResource));

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                              ID3D12Resource* pCommittedResource,
                                              IResourceAllocation** ppResourceAllocationOut) {
        return E_NOTIMPL;
    }

    HRESULT ResourceAllocator::ReleaseResourceHeaps(uint64_t bytesToRelease, uint64_t* pBytesReleased) {
        return E_NOTIMPL;
    }

    HRESULT ResourceAllocator::QueryStats(RESOURCE_ALLOCATOR_STATS* pResourceAllocatorStats) {
        return E_NOTIMPL;
    }

    HRESULT ResourceAllocator::CheckFeatureSupport(ALLOCATOR_FEATURE feature,
                                                   void* pFeatureSupportData,
                                                   uint32_t featureSupportDataSize) const {
        return E_INVALIDARG;  // Unsupported
    }

    ResourceAllocator::ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                                         ResidencyManager* pResidencyManager)
        : mDevice(std::move(descriptor.Device)), mResidencyManager(pResidencyManager) {
    }

    void ResourceAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        const uint64_t& allocationSize = allocation->GetSize();
        mStats.UsedMemoryUsage -= allocationSize;
        mStats.UsedMemoryCount--;
        mStats.UsedBlockUsage -= allocationSize;
        delete allocation->GetMemory();
    }

    HRESULT STDMETHODCALLTYPE ResourceAllocator::QueryInterface(REFIID riid, void** ppvObject) {
        return Unknown::QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResourceAllocator::AddRef() {
        return Unknown::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResourceAllocator::Release() {
        return Unknown::Release();
    }

    LPCWSTR ResourceAllocator::GetDebugName() const {
        return L"";
    }

    HRESULT ResourceAllocator::SetDebugName(LPCWSTR Name) {
        return S_OK;
    }

    CreateCommittedResourceCallbackContext::CreateCommittedResourceCallbackContext(
        ID3D12Device* device,
        ALLOCATION_DESC allocationDescriptor,
        Microsoft::WRL::ComPtr<ID3D12Resource> resource,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* clearValue,
        D3D12_RESOURCE_STATES initialResourceState)
        : mDevice(device),
          mAllocationDescriptor(allocationDescriptor),
          mClearValue(clearValue),
          mResource(resource),
          mResourceDescriptor(resourceDescriptor) {
    }

    HRESULT CreateCommittedResourceCallbackContext::CreateCommittedResource(
        ID3D12Pageable** ppPageableOut) {
        D3D12_HEAP_PROPERTIES heapProperties = {};
        heapProperties.Type = mAllocationDescriptor.HeapType;

        ReturnIfFailed(mDevice->CreateCommittedResource(&heapProperties, D3D12_HEAP_FLAG_NONE,
                                                        mResourceDescriptor, mInitialResourceState,
                                                        mClearValue, IID_PPV_ARGS(&mResource)));

        Microsoft::WRL::ComPtr<ID3D12Pageable> pageable;
        ReturnIfFailed(mResource.As(&pageable));
        *ppPageableOut = pageable.Detach();
        return S_OK;
    }

    HRESULT CreateCommittedResourceCallbackContext::CreateHeap(void* context,
                                                               ID3D12Pageable** ppPageableOut) {
        CreateCommittedResourceCallbackContext* createCommittedResourceCallbackContext =
            static_cast<CreateCommittedResourceCallbackContext*>(context);

        return createCommittedResourceCallbackContext->CreateCommittedResource(ppPageableOut);
    }

}  // namespace gpgmm::d3d12
