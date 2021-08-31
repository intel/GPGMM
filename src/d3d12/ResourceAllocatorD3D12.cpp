// Copyright 2019 The Dawn Authors
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

#include "src/d3d12/ResourceAllocatorD3D12.h"

#include "src/PooledMemoryAllocator.h"
#include "src/VirtualBuddyAllocator.h"
#include "src/common/Limits.h"
#include "src/common/Math.h"
#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/ResidencyManagerD3D12.h"
#include "src/d3d12/ResourceHeapAllocatorD3D12.h"

namespace gpgmm { namespace d3d12 {
    namespace {
        DXGI_MEMORY_SEGMENT_GROUP GetPreferredMemorySegmentGroup(ID3D12Device* device,
                                                                 bool isUMA,
                                                                 D3D12_HEAP_TYPE heapType) {
            if (isUMA) {
                return DXGI_MEMORY_SEGMENT_GROUP_LOCAL;
            }

            D3D12_HEAP_PROPERTIES heapProperties = device->GetCustomHeapProperties(0, heapType);

            if (heapProperties.MemoryPoolPreference == D3D12_MEMORY_POOL_L1) {
                return DXGI_MEMORY_SEGMENT_GROUP_LOCAL;
            }

            return DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL;
        }

        D3D12_RESOURCE_ALLOCATION_INFO GetResourceAllocationInfo(
            ID3D12Device* device,
            D3D12_RESOURCE_DESC& resourceDescriptor) {
            // Buffers are always 64KB size-aligned and resource-aligned. See Remarks.
            // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12device-getresourceallocationinfo
            if (resourceDescriptor.Alignment == 0 &&
                resourceDescriptor.Dimension == D3D12_RESOURCE_DIMENSION_BUFFER) {
                return {Align(resourceDescriptor.Width, D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT),
                        D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT};
            }

            // Small textures can take advantage of smaller alignments. For example,
            // if the most detailed mip can fit under 64KB, 4KB alignments can be used.
            // Must be non-depth or without render-target to use small resource alignment.
            // This also applies to MSAA textures (4MB => 64KB).
            // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_resource_desc
            if ((resourceDescriptor.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE1D ||
                 resourceDescriptor.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE2D ||
                 resourceDescriptor.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE3D) &&
                (resourceDescriptor.Flags & (D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET |
                                             D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL)) == 0) {
                resourceDescriptor.Alignment = (resourceDescriptor.SampleDesc.Count > 1)
                                                   ? D3D12_SMALL_MSAA_RESOURCE_PLACEMENT_ALIGNMENT
                                                   : D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT;
            }

            D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
                device->GetResourceAllocationInfo(0, 1, &resourceDescriptor);

            // If the requested resource alignment was rejected, let D3D tell us what the
            // required alignment is for this resource.
            if (resourceDescriptor.Alignment != 0 &&
                resourceDescriptor.Alignment != resourceInfo.Alignment) {
                resourceDescriptor.Alignment = 0;
                resourceInfo = device->GetResourceAllocationInfo(0, 1, &resourceDescriptor);
            }

            if (resourceInfo.SizeInBytes == 0) {
                resourceInfo.SizeInBytes = std::numeric_limits<uint64_t>::max();
            }

            return resourceInfo;
        }

        D3D12_HEAP_TYPE GetHeapType(ResourceHeapKind resourceHeapKind) {
            switch (resourceHeapKind) {
                case Readback_OnlyBuffers:
                case Readback_AllBuffersAndTextures:
                    return D3D12_HEAP_TYPE_READBACK;
                case Default_AllBuffersAndTextures:
                case Default_OnlyBuffers:
                case Default_OnlyNonRenderableOrDepthTextures:
                case Default_OnlyRenderableOrDepthTextures:
                    return D3D12_HEAP_TYPE_DEFAULT;
                case Upload_OnlyBuffers:
                case Upload_AllBuffersAndTextures:
                    return D3D12_HEAP_TYPE_UPLOAD;
                case EnumCount:
                    UNREACHABLE();
            }
        }

        D3D12_HEAP_FLAGS GetHeapFlags(ResourceHeapKind resourceHeapKind) {
            switch (resourceHeapKind) {
                case Default_AllBuffersAndTextures:
                case Readback_AllBuffersAndTextures:
                case Upload_AllBuffersAndTextures:
                    return D3D12_HEAP_FLAG_ALLOW_ALL_BUFFERS_AND_TEXTURES;
                case Default_OnlyBuffers:
                case Readback_OnlyBuffers:
                case Upload_OnlyBuffers:
                    return D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS;
                case Default_OnlyNonRenderableOrDepthTextures:
                    return D3D12_HEAP_FLAG_ALLOW_ONLY_NON_RT_DS_TEXTURES;
                case Default_OnlyRenderableOrDepthTextures:
                    return D3D12_HEAP_FLAG_ALLOW_ONLY_RT_DS_TEXTURES;
                case EnumCount:
                    UNREACHABLE();
            }
        }

        ResourceHeapKind GetResourceHeapKind(D3D12_RESOURCE_DIMENSION dimension,
                                             D3D12_HEAP_TYPE heapType,
                                             D3D12_RESOURCE_FLAGS flags,
                                             uint32_t resourceHeapTier) {
            if (resourceHeapTier >= 2) {
                switch (heapType) {
                    case D3D12_HEAP_TYPE_UPLOAD:
                        return Upload_AllBuffersAndTextures;
                    case D3D12_HEAP_TYPE_DEFAULT:
                        return Default_AllBuffersAndTextures;
                    case D3D12_HEAP_TYPE_READBACK:
                        return Readback_AllBuffersAndTextures;
                    default:
                        UNREACHABLE();
                }
            }

            switch (dimension) {
                case D3D12_RESOURCE_DIMENSION_BUFFER: {
                    switch (heapType) {
                        case D3D12_HEAP_TYPE_UPLOAD:
                            return Upload_OnlyBuffers;
                        case D3D12_HEAP_TYPE_DEFAULT:
                            return Default_OnlyBuffers;
                        case D3D12_HEAP_TYPE_READBACK:
                            return Readback_OnlyBuffers;
                        default:
                            UNREACHABLE();
                    }
                    break;
                }
                case D3D12_RESOURCE_DIMENSION_TEXTURE1D:
                case D3D12_RESOURCE_DIMENSION_TEXTURE2D:
                case D3D12_RESOURCE_DIMENSION_TEXTURE3D: {
                    switch (heapType) {
                        case D3D12_HEAP_TYPE_DEFAULT: {
                            if ((flags & D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL) ||
                                (flags & D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET)) {
                                return Default_OnlyRenderableOrDepthTextures;
                            }
                            return Default_OnlyNonRenderableOrDepthTextures;
                        }

                        default:
                            UNREACHABLE();
                    }
                    break;
                }
                default:
                    UNREACHABLE();
            }
        }
    }  // namespace

    ResourceAllocator::ResourceAllocator(const ALLOCATOR_DESC& descriptor)
        : mDevice(descriptor.Device),
          mIsUMA(descriptor.IsUMA),
          mResourceHeapTier(descriptor.ResourceHeapTier),
          mIsAlwaysCommitted(descriptor.Flags & ALLOCATOR_ALWAYS_COMMITED),
          mIsAlwaysInBudget(descriptor.Flags & ALLOCATOR_ALWAYS_IN_BUDGET),
          mMaxResourceSizeForPooling(descriptor.MaxResourceSizeForPooling),
          mResidencyManager(new ResidencyManager(mDevice,
                                                 descriptor.Adapter,
                                                 mIsUMA,
                                                 descriptor.TotalMemorySegmentBudgetLimit)) {
        const uint64_t heapSize = (descriptor.PreferredResourceHeapSize > 0)
                                      ? descriptor.PreferredResourceHeapSize
                                      : kDefaultHeapSize;

        for (uint32_t i = 0; i < ResourceHeapKind::EnumCount; i++) {
            const ResourceHeapKind resourceHeapKind = static_cast<ResourceHeapKind>(i);

            // It is preferred to use a size that is a multiple of the alignment.
            // However, MSAA heaps are always aligned to 4MB instead of 64KB. This means
            // if the heap size is too small, the VMM would fragment.
            // TODO(crbug.com/dawn/849): Consider having MSAA vs non-MSAA heaps.
            constexpr uint64_t heapAlignment = D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT;

            mResourceHeapAllocators[i] = std::make_unique<ResourceHeapAllocator>(
                this, GetHeapType(resourceHeapKind), GetHeapFlags(resourceHeapKind),
                GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA,
                                               GetHeapType(resourceHeapKind)),
                heapSize, heapAlignment);
            mPooledResourceHeapAllocators[i] =
                std::make_unique<PooledMemoryAllocator>(mResourceHeapAllocators[i].get());
            mPooledPlacedAllocators[i] = std::make_unique<VirtualBuddyAllocator>(
                kMaxHeapSize, mPooledResourceHeapAllocators[i].get());

            // Non-pooled buddy allocator variant
            mPlacedAllocators[i] = std::make_unique<VirtualBuddyAllocator>(
                kMaxHeapSize, mResourceHeapAllocators[i].get());
        }
    }

    ResourceAllocator::~ResourceAllocator() {
        ReleaseMemory();
    }

    HRESULT ResourceAllocator::CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                              const D3D12_RESOURCE_DESC& resourceDescriptor,
                                              D3D12_RESOURCE_STATES initialUsage,
                                              const D3D12_CLEAR_VALUE* clearValue,
                                              ResourceAllocation** ppResourceAllocation) {
        // If d3d tells us the resource size is invalid, treat the error as OOM.
        // Otherwise, creating the resource could cause a device loss (too large).
        // This is because NextPowerOfTwo(UINT64_MAX) overflows and proceeds to
        // incorrectly allocate a mismatched size.
        D3D12_RESOURCE_DESC newResourceDesc = resourceDescriptor;
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), newResourceDesc);
        if (resourceInfo.SizeInBytes == std::numeric_limits<uint64_t>::max()) {
            return E_OUTOFMEMORY;
        }

        // TODO(crbug.com/dawn/849): Conditionally disable sub-allocation.
        // For very large resources, there is no benefit to suballocate.
        // For very small resources, it is inefficent to suballocate given the min. heap
        // size could be much larger then the resource allocation.
        // Attempt to satisfy the request using sub-allocation (placed resource in a heap).
        HRESULT hr = E_UNEXPECTED;
        if (!mIsAlwaysCommitted) {

            const ResourceHeapKind resourceHeapKind = GetResourceHeapKind(
                newResourceDesc.Dimension, allocationDescriptor.HeapType, newResourceDesc.Flags, mResourceHeapTier);

            VirtualBuddyAllocator* allocator = nullptr;
            if (mMaxResourceSizeForPooling != 0 &&
                resourceInfo.SizeInBytes > mMaxResourceSizeForPooling) {
                allocator = mPooledPlacedAllocators[static_cast<size_t>(resourceHeapKind)].get();
            } else {
                allocator = mPlacedAllocators[static_cast<size_t>(resourceHeapKind)].get();
            }

            hr = CreatePlacedResource(allocator, resourceInfo, &newResourceDesc,
                                      clearValue, initialUsage, ppResourceAllocation);
        }
        // If sub-allocation fails, fall-back to direct allocation (committed resource).
        if (FAILED(hr)) {
            hr = CreateCommittedResource(allocationDescriptor.HeapType, resourceInfo,
                                         &newResourceDesc, clearValue, initialUsage,
                                         ppResourceAllocation);
        }
        return hr;
    }

    HRESULT ResourceAllocator::CreateResource(ComPtr<ID3D12Resource> resource,
                                              ResourceAllocation** ppResourceAllocation) {
        D3D12_RESOURCE_DESC desc = resource->GetDesc();
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), desc);

        D3D12_HEAP_PROPERTIES heapProp;
        HRESULT hr = resource->GetHeapProperties(&heapProp, nullptr);
        if (FAILED(hr)) {
            return hr;
        }

        // Do not track imported resources for purposes of residency.
        Heap* heap =
            new Heap(resource, GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapProp.Type),
                     resourceInfo.SizeInBytes);

        gpgmm::AllocationInfo info;
        info.mMethod = gpgmm::AllocationMethod::kStandalone;

        *ppResourceAllocation = new ResourceAllocation{/*residencyManager*/ nullptr,
                                                       /*memoryAllocator*/ this,
                                                       info,
                                                       /*offset*/ 0,
                                                       std::move(resource),
                                                       heap};
        return hr;
    }

    HRESULT ResourceAllocator::CreatePlacedResource(
        MemoryAllocator* allocator,
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* pClearValue,
        D3D12_RESOURCE_STATES initialUsage,
        ResourceAllocation** ppResourceAllocation) {
        if (!ppResourceAllocation) {
            return E_POINTER;
        }

        ASSERT(allocator != nullptr);

        MemoryAllocation subAllocation;
        allocator->SubAllocateMemory(resourceInfo.SizeInBytes, resourceInfo.Alignment,
                                     subAllocation);
        if (subAllocation == GPGMM_INVALID_ALLOCATION) {
            return E_INVALIDARG;
        }

        // Before calling CreatePlacedResource, we must ensure the target heap is resident.
        // CreatePlacedResource will fail if it is not.
        HRESULT hr = S_OK;
        Heap* heap = static_cast<Heap*>(subAllocation.GetMemory());
        if (mIsAlwaysInBudget) {
            hr = mResidencyManager->LockHeap(heap);
            if (FAILED(hr)) {
                return hr;
            }
        }

        // With placed resources, a single heap can be reused.
        // The resource placed at an offset is only reclaimed
        // upon Tick or after the last command list using the resource has completed
        // on the GPU. This means the same physical memory is not reused
        // within the same command-list and does not require additional synchronization (aliasing
        // barrier).
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12device-createplacedresource
        ComPtr<ID3D12Resource> placedResource;
        hr = mDevice->CreatePlacedResource(heap->GetD3D12Heap(), subAllocation.GetOffset(),
                                           resourceDescriptor, initialUsage, pClearValue,
                                           IID_PPV_ARGS(&placedResource));
        if (FAILED(hr)) {
            return hr;
        }

        // After CreatePlacedResource has finished, the heap can be unlocked from residency. This
        // will insert it into the residency LRU.
        if (mIsAlwaysInBudget) {
            mResidencyManager->UnlockHeap(heap);
        }

        *ppResourceAllocation =
            new ResourceAllocation{mResidencyManager.get(),   allocator,
                                   subAllocation.GetInfo(),   subAllocation.GetOffset(),
                                   std::move(placedResource), heap};
        return hr;
    }

    HRESULT ResourceAllocator::CreateResourceHeap(uint64_t size,
                                                  D3D12_HEAP_TYPE heapType,
                                                  D3D12_HEAP_FLAGS heapFlags,
                                                  DXGI_MEMORY_SEGMENT_GROUP memorySegment,
                                                  uint64_t heapAlignment,
                                                  Heap** ppResourceHeap) {
        D3D12_HEAP_DESC heapDesc;
        heapDesc.SizeInBytes = size;
        heapDesc.Properties.Type = heapType;
        heapDesc.Properties.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
        heapDesc.Properties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
        heapDesc.Properties.CreationNodeMask = 0;
        heapDesc.Properties.VisibleNodeMask = 0;
        heapDesc.Alignment = heapAlignment;
        heapDesc.Flags = heapFlags;

        // CreateHeap will implicitly make the created heap resident. We must ensure enough free
        // memory exists before allocating to avoid an out-of-memory error when overcommitted.
        if (mIsAlwaysInBudget) {
            mResidencyManager->Evict(size, memorySegment);
        }

        ComPtr<ID3D12Heap> d3d12Heap;
        HRESULT hr = mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&d3d12Heap));
        if (FAILED(hr)) {
            return hr;
        }

        *ppResourceHeap = new Heap(std::move(d3d12Heap), memorySegment, size);

        // Calling CreateHeap implicitly calls MakeResident on the new heap. We must track this to
        // avoid calling MakeResident a second time.
        if (mIsAlwaysInBudget) {
            mResidencyManager->InsertHeap(*ppResourceHeap);
        }

        return hr;
    }

    HRESULT ResourceAllocator::CreateCommittedResource(
        D3D12_HEAP_TYPE heapType,
        const D3D12_RESOURCE_ALLOCATION_INFO& resourceInfo,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* pClearValue,
        D3D12_RESOURCE_STATES initialUsage,
        ResourceAllocation** ppResourceAllocation) {
        if (!ppResourceAllocation) {
            return E_POINTER;
        }

        D3D12_HEAP_PROPERTIES heapProperties;
        heapProperties.Type = heapType;
        heapProperties.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
        heapProperties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
        heapProperties.CreationNodeMask = 0;
        heapProperties.VisibleNodeMask = 0;

        if (resourceInfo.SizeInBytes > kMaxHeapSize) {
            return E_OUTOFMEMORY;
        }

        // CreateCommittedResource will implicitly make the created resource resident. We must
        // ensure enough free memory exists before allocating to avoid an out-of-memory error when
        // overcommitted.
        HRESULT hr = S_OK;
        if (mIsAlwaysInBudget) {
            hr = mResidencyManager->Evict(
                resourceInfo.SizeInBytes,
                GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapType));
            if (FAILED(hr)) {
                return hr;
            }
        }

        // Note: Heap flags are inferred by the resource descriptor and do not need to be explicitly
        // provided to CreateCommittedResource.
        ComPtr<ID3D12Resource> committedResource;
        hr = mDevice->CreateCommittedResource(&heapProperties, D3D12_HEAP_FLAG_NONE,
                                              resourceDescriptor, initialUsage, pClearValue,
                                              IID_PPV_ARGS(&committedResource));
        if (FAILED(hr)) {
            return hr;
        }

        // When using CreateCommittedResource, D3D12 creates an implicit heap that contains the
        // resource allocation. Because Dawn's memory residency management occurs at the resource
        // heap granularity, every directly allocated ResourceAllocation also stores a Heap
        // object. This object is created manually, and must be deleted manually upon deallocation
        // of the committed resource.
        Heap* heap = new Heap(committedResource,
                              GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapType),
                              resourceInfo.SizeInBytes);

        // Calling CreateCommittedResource implicitly calls MakeResident on the resource. We must
        // track this to avoid calling MakeResident a second time.
        if (mIsAlwaysInBudget) {
            mResidencyManager->InsertHeap(heap);
        }

        AllocationInfo info = {};
        info.mMethod = AllocationMethod::kStandalone;

        *ppResourceAllocation = new ResourceAllocation{mResidencyManager.get(),
                                                       /*memoryAllocator*/ this,
                                                       info,
                                                       /*offset*/ 0,
                                                       std::move(committedResource),
                                                       heap};
        return hr;
    }

    void ResourceAllocator::SubAllocateMemory(uint64_t size,
                                              uint64_t alignment,
                                              MemoryAllocation& allocation) {
        ASSERT(false);
    }

    void ResourceAllocator::AllocateMemory(MemoryAllocation** ppAllocation) {
        ASSERT(false);
    }

    void ResourceAllocator::DeallocateMemory(MemoryAllocation* pResourceHeap) {
        ASSERT(pResourceHeap != nullptr);
        ASSERT(pResourceHeap->GetInfo().mMethod == gpgmm::AllocationMethod::kStandalone);
        ASSERT(pResourceHeap->GetMemory() != nullptr);

        delete pResourceHeap->GetMemory();
    }

    void ResourceAllocator::ReleaseMemory() {
        for (auto& allocator : mPooledPlacedAllocators) {
            allocator->ReleaseMemory();
        }
    }

    uint64_t ResourceAllocator::GetMemorySize() const {
        ASSERT(false);
        return kInvalidSize;
    }

    uint64_t ResourceAllocator::GetMemoryAlignment() const {
        ASSERT(false);
        return kInvalidOffset;
    }

    ResidencyManager* ResourceAllocator::GetResidencyManager() {
        return mResidencyManager.get();
    }

}}  // namespace gpgmm::d3d12
