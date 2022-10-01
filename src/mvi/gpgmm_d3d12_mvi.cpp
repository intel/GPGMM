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

#include "gpgmm_d3d12_mvi.h"

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
                             IResidencyManager* const pResidencyManager,
                             CreateHeapFn&& createHeapFn,
                             IHeap** ppHeapOut) {
        Microsoft::WRL::ComPtr<ID3D12Pageable> pageable;
        ReturnIfFailed(createHeapFn(&pageable));

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
        return {};
    }

    bool Heap::IsInResidencyLRUCacheForTesting() const {
        return false;
    }

    bool Heap::IsResidencyLockedForTesting() const {
        return false;
    }

    HRESULT STDMETHODCALLTYPE Heap::QueryInterface(REFIID riid, void** ppvObject) {
        return mPageable->QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE Heap::AddRef() {
        return IUnknownImpl::AddRef();
    }

    ULONG STDMETHODCALLTYPE Heap::Release() {
        return IUnknownImpl::Release();
    }

    uint64_t Heap::GetSize() const {
        return MemoryBase::GetSize();
    }

    uint64_t Heap::GetAlignment() const {
        return MemoryBase::GetAlignment();
    }

    void Heap::AddSubAllocationRef() {
    }

    bool Heap::RemoveSubAllocationRef() {
        return true;
    }

    LPCWSTR Heap::GetDebugName() const {
        return nullptr;
    }

    HRESULT Heap::SetDebugName(LPCWSTR Name) {
        return E_NOTIMPL;
    }

    IMemoryPool* Heap::GetPool() const {
        return nullptr;
    }

    void Heap::SetPool(IMemoryPool* pool) {
    }

    // ResidencyList

    HRESULT CreateResidencyList(IResidencyList** ppResidencyList) {
        if (ppResidencyList != nullptr) {
            *ppResidencyList = new ResidencyList();
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
        return IUnknownImpl::QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResidencyList::AddRef() {
        return IUnknownImpl::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResidencyList::Release() {
        return IUnknownImpl::Release();
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

    RESIDENCY_STATS ResidencyManager::GetStats() const {
        return {0, 0};
    }

    ResidencyManager::ResidencyManager(const RESIDENCY_DESC& descriptor)
        : mDevice(std::move(descriptor.Device)), mAdapter(std::move(descriptor.Adapter)) {
    }

    HRESULT STDMETHODCALLTYPE ResidencyManager::QueryInterface(REFIID riid, void** ppvObject) {
        return IUnknownImpl::QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResidencyManager::AddRef() {
        return IUnknownImpl::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResidencyManager::Release() {
        return IUnknownImpl::Release();
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

    ResourceAllocation::ResourceAllocation(const RESOURCE_ALLOCATION_DESC& desc,
                                           MemoryAllocator* allocator,
                                           IHeap* resourceHeap,
                                           Microsoft::WRL::ComPtr<ID3D12Resource> resource)
        : MemoryAllocation(allocator, resourceHeap), mResource(std::move(resource)) {
    }

    HRESULT STDMETHODCALLTYPE ResourceAllocation::QueryInterface(REFIID riid, void** ppvObject) {
        return IUnknownImpl::QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResourceAllocation::AddRef() {
        return IUnknownImpl::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResourceAllocation::Release() {
        return IUnknownImpl::Release();
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
        if (allocatorDescriptor.Device == nullptr || allocatorDescriptor.Adapter == nullptr) {
            return E_INVALIDARG;
        }

        Microsoft::WRL::ComPtr<IResidencyManager> residencyManager;
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
            *ppResourceAllocatorOut = new ResourceAllocator(allocatorDescriptor, pResidencyManager);
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
        mStats.UsedMemoryUsage += allocationSize;
        mStats.UsedMemoryCount++;
        mStats.UsedBlockUsage += allocationSize;

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
        IResourceAllocation** ppResourceAllocationOut) {
        return E_NOTIMPL;
    }

    uint64_t ResourceAllocator::ReleaseMemory(uint64_t bytesToRelease) {
        return 0;
    }

    RESOURCE_ALLOCATOR_STATS ResourceAllocator::GetStats() const {
        return mStats;
    }

    HRESULT ResourceAllocator::CheckFeatureSupport(ALLOCATOR_FEATURE feature,
                                                   void* pFeatureSupportData,
                                                   uint32_t featureSupportDataSize) const {
        return E_INVALIDARG;  // Unsupported
    }

    ResourceAllocator::ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                                         IResidencyManager* pResidencyManager)
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
        return IUnknownImpl::QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE ResourceAllocator::AddRef() {
        return IUnknownImpl::AddRef();
    }

    ULONG STDMETHODCALLTYPE ResourceAllocator::Release() {
        return IUnknownImpl::Release();
    }

}  // namespace gpgmm::d3d12
