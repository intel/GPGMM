// Copyright 2019 The Dawn Authors
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

#include "src/d3d12/ResourceAllocatorD3D12.h"

#include "../common/Math.h"
#include "src/ConditionalMemoryAllocator.h"
#include "src/LIFOPooledMemoryAllocator.h"
#include "src/MemoryAllocatorStack.h"
#include "src/TraceEvent.h"
#include "src/VirtualBuddyMemoryAllocator.h"
#include "src/d3d12/DefaultsD3D12.h"
#include "src/d3d12/HeapD3D12.h"
#include "src/d3d12/JSONSerializerD3D12.h"
#include "src/d3d12/ResidencyManagerD3D12.h"
#include "src/d3d12/ResourceAllocationD3D12.h"
#include "src/d3d12/ResourceHeapAllocatorD3D12.h"
#include "src/d3d12/UtilsD3D12.h"

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
                default:
                    UNREACHABLE();
                    return D3D12_HEAP_TYPE_DEFAULT;
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
                default:
                    UNREACHABLE();
                    return D3D12_HEAP_FLAG_NONE;
            }
        }

        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_flags
        uint64_t GetHeapAlignment(D3D12_HEAP_FLAGS heapFlags) {
            const D3D12_HEAP_FLAGS denyAllTexturesFlags =
                D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES | D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES;
            if ((heapFlags & denyAllTexturesFlags) == denyAllTexturesFlags) {
                return D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT;
            }
            // It is preferred to use a size that is a multiple of the alignment.
            // However, MSAA heaps are always aligned to 4MB instead of 64KB. This means
            // if the heap size is too small, the VMM would fragment.
            // TODO: Consider having MSAA vs non-MSAA heaps.
            return D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT;
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
                        return ResourceHeapKind::InvalidEnum;
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
                    return ResourceHeapKind::InvalidEnum;
            }

            return ResourceHeapKind::InvalidEnum;
        }

        // RAII wrapper to lock/unlock heap from the residency cache.
        class ScopedHeapLock {
          public:
            ScopedHeapLock(ResidencyManager* residencyManager, Heap* heap)
                : mResidencyManager(residencyManager), mHeap(heap) {
                ASSERT(heap != nullptr);
                if (mResidencyManager != nullptr) {
                    mResidencyManager->LockHeap(mHeap);
                }
            }

            ~ScopedHeapLock() {
                if (mResidencyManager != nullptr) {
                    mResidencyManager->UnlockHeap(mHeap);
                }
            }

            ScopedHeapLock(const ScopedHeapLock&) = delete;
            ScopedHeapLock& operator=(const ScopedHeapLock&) = delete;

          private:
            ResidencyManager* const mResidencyManager;
            Heap* const mHeap;
        };

    }  // namespace

    // static
    HRESULT ResourceAllocator::CreateAllocator(const ALLOCATOR_DESC& descriptor,
                                               ResourceAllocator** resourceAllocator) {
        if (descriptor.Adapter == nullptr || descriptor.Device == nullptr) {
            return E_INVALIDARG;
        }

        const uint64_t minResourceHeapSize = (descriptor.PreferredResourceHeapSize > 0)
                                                 ? descriptor.PreferredResourceHeapSize
                                                 : kDefaultPreferredResourceHeapSize;

        const uint64_t maxResourceHeapSize = (descriptor.MaxResourceHeapSize > 0)
                                                 ? descriptor.MaxResourceHeapSize
                                                 : kDefaultMaxResourceHeapSize;

        bool enableEventTracer = descriptor.RecordOptions.Flags & ALLOCATOR_RECORD_TRACE_EVENTS;
#ifdef GPGMM_ALWAYS_RECORD_EVENT_TRACE
        enableEventTracer = true;
#endif

        if (enableEventTracer) {
            StartupEventTracer(descriptor.RecordOptions.TraceFile);
        }

        // Must StartupEventTracer before tracing any class.
        GPGMM_API_TRACE_FUNCTION_CALL(descriptor);

        std::unique_ptr<ResidencyManager> residencyManager;
        ResidencyManager* residencyManagerPtr = nullptr;
        if (SUCCEEDED(ResidencyManager::CreateResidencyManager(
                descriptor.Device, descriptor.Adapter, descriptor.IsUMA,
                descriptor.MaxVideoMemoryBudget, descriptor.TotalResourceBudgetLimit,
                &residencyManagerPtr))) {
            residencyManager = std::unique_ptr<ResidencyManager>(residencyManagerPtr);
        }

        *resourceAllocator = new ResourceAllocator(
            descriptor.Device, std::move(residencyManager), descriptor.IsUMA,
            descriptor.ResourceHeapTier, descriptor.Flags, descriptor.MaxResourceSizeForPooling,
            minResourceHeapSize, maxResourceHeapSize);

        return S_OK;
    }

    ResourceAllocator::ResourceAllocator(Microsoft::WRL::ComPtr<ID3D12Device> device,
                                         std::unique_ptr<ResidencyManager> residencyManager,
                                         bool isUMA,
                                         uint32_t resourceHeapTier,
                                         ALLOCATOR_FLAGS allocatorFlags,
                                         uint64_t maxResourceSizeForPooling,
                                         uint64_t minResourceHeapSize,
                                         uint64_t maxResourceHeapSize)
        : mDevice(std::move(device)),
          mResidencyManager(std::move(residencyManager)),
          mIsUMA(isUMA),
          mResourceHeapTier(resourceHeapTier),
          mIsAlwaysCommitted(allocatorFlags & ALLOCATOR_ALWAYS_COMMITED),
          mIsAlwaysInBudget(allocatorFlags & ALLOCATOR_ALWAYS_IN_BUDGET),
          mMaxResourceHeapSize(maxResourceHeapSize) {
        GPGMM_OBJECT_NEW_INSTANCE("ResourceAllocator");

        for (uint32_t i = 0; i < ResourceHeapKind::EnumCount; i++) {
            const ResourceHeapKind resourceHeapKind = static_cast<ResourceHeapKind>(i);

            const D3D12_HEAP_FLAGS heapFlags = GetHeapFlags(resourceHeapKind);
            const uint64_t heapAlignment = GetHeapAlignment(heapFlags);
            const D3D12_HEAP_TYPE heapType = GetHeapType(resourceHeapKind);

            std::unique_ptr<MemoryAllocatorStack> stack = std::make_unique<MemoryAllocatorStack>();

            // Standalone heap allocator.
            MemoryAllocator* heapAllocator =
                stack->PushAllocator(std::make_unique<ResourceHeapAllocator>(
                    this, heapType, heapFlags, minResourceHeapSize));

            // Placed resource sub-allocator.
            MemoryAllocator* subAllocator =
                stack->PushAllocator(std::make_unique<VirtualBuddyMemoryAllocator>(
                    mMaxResourceHeapSize, minResourceHeapSize, heapAlignment, heapAllocator));

            // Pooled standalone heap allocator.
            MemoryAllocator* pooledHeapAllocator =
                stack->PushAllocator(std::make_unique<LIFOPooledMemoryAllocator>(heapAllocator));

            // Pooled placed resource sub-allocator.
            MemoryAllocator* pooledSubAllocator =
                stack->PushAllocator(std::make_unique<VirtualBuddyMemoryAllocator>(
                    mMaxResourceHeapSize, minResourceHeapSize, heapAlignment, pooledHeapAllocator));

            // Conditional sub-allocator that uses the pooled or non-pooled sub-allocator.
            stack->PushAllocator(std::make_unique<ConditionalMemoryAllocator>(
                pooledSubAllocator, subAllocator, maxResourceSizeForPooling));

            mSubAllocators[i] = std::move(stack);
        }
    }

    ResourceAllocator::~ResourceAllocator() {
        GPGMM_OBJECT_DELETE_INSTANCE("ResourceAllocator");

        for (auto& allocator : mSubAllocators) {
            ASSERT(allocator != nullptr);
            allocator->ReleaseMemory();
        }

        ShutdownEventTracer();
    }

    HRESULT ResourceAllocator::CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                              const D3D12_RESOURCE_DESC& resourceDescriptor,
                                              D3D12_RESOURCE_STATES initialUsage,
                                              const D3D12_CLEAR_VALUE* clearValue,
                                              ResourceAllocation** resourceAllocationOut) {
        GPGMM_API_TRACE_FUNCTION_BEGIN();

        const CREATE_RESOURCE_DESC desc = {allocationDescriptor, resourceDescriptor, initialUsage,
                                           clearValue};

        GPGMM_API_TRACE_FUNCTION_CALL(desc);

        // If d3d tells us the resource size is invalid, treat the error as OOM.
        // Otherwise, creating a very large resource could overflow the allocator.
        D3D12_RESOURCE_DESC newResourceDesc = resourceDescriptor;
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), newResourceDesc);
        if (resourceInfo.SizeInBytes == std::numeric_limits<uint64_t>::max()) {
            return E_OUTOFMEMORY;
        }

        if (resourceInfo.SizeInBytes > mMaxResourceHeapSize) {
            return E_OUTOFMEMORY;
        }

        const ResourceHeapKind resourceHeapKind =
            GetResourceHeapKind(newResourceDesc.Dimension, allocationDescriptor.HeapType,
                                newResourceDesc.Flags, mResourceHeapTier);

        // TODO(crbug.com/dawn/849): Conditionally disable sub-allocation.
        // For very large resources, there is no benefit to suballocate.
        // For very small resources, it is inefficent to suballocate given the min. heap
        // size could be much larger then the resource allocation.
        // Attempt to satisfy the request using sub-allocation (placed resource in a heap).
        if (!mIsAlwaysCommitted) {
            MemoryAllocator* subAllocator =
                mSubAllocators[static_cast<size_t>(resourceHeapKind)].get();

            ReturnIfSucceeded(TryAllocateResource(
                subAllocator, resourceInfo.SizeInBytes, resourceInfo.Alignment,
                [&](auto subAllocation) -> HRESULT {
                    return CreatePlacedResource(subAllocation, resourceInfo, &newResourceDesc,
                                                clearValue, initialUsage, resourceAllocationOut);
                }));
        }

        ReturnIfFailed(CreateCommittedResource(
            allocationDescriptor.HeapType, GetHeapFlags(resourceHeapKind), resourceInfo,
            &newResourceDesc, clearValue, initialUsage, resourceAllocationOut));

        GPGMM_API_TRACE_FUNCTION_END();
        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResource(ComPtr<ID3D12Resource> committedResource,
                                              ResourceAllocation** resourceAllocationOut) {
        GPGMM_API_TRACE_FUNCTION_BEGIN();

        if (committedResource == nullptr) {
            return E_INVALIDARG;
        }

        D3D12_RESOURCE_DESC desc = committedResource->GetDesc();
        GPGMM_API_TRACE_FUNCTION_CALL(desc);

        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), desc);

        D3D12_HEAP_PROPERTIES heapProp;
        ReturnIfFailed(committedResource->GetHeapProperties(&heapProp, nullptr));

        // Do not track imported resources for purposes of residency.
        Heap* heap =
            new Heap(committedResource,
                     GetPreferredMemorySegmentGroup(mDevice.Get(), /*IsUMA*/ false, heapProp.Type),
                     resourceInfo.SizeInBytes);

        gpgmm::AllocationInfo info;
        info.mMethod = gpgmm::AllocationMethod::kStandalone;

        *resourceAllocationOut =
            new ResourceAllocation{/*residencyManager*/ nullptr,
                                   /*allocator*/ this, info, std::move(committedResource), heap};

        GPGMM_API_TRACE_FUNCTION_END();
        return S_OK;
    }

    HRESULT ResourceAllocator::CreatePlacedResource(
        const MemoryAllocation& subAllocation,
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* clearValue,
        D3D12_RESOURCE_STATES initialUsage,
        ResourceAllocation** resourceAllocationOut) {
        if (!resourceAllocationOut) {
            return E_POINTER;
        }

        // Must place a resource using a sub-allocated memory allocation.
        if (subAllocation.GetInfo().mMethod != AllocationMethod::kSubAllocated) {
            return E_FAIL;
        }

        // Sub-allocation cannot be smaller than the resource being placed.
        if (subAllocation.GetInfo().mBlock == nullptr ||
            subAllocation.GetInfo().mBlock->mSize < resourceInfo.SizeInBytes) {
            return E_FAIL;
        }

        // Before calling CreatePlacedResource, we must ensure the target heap is resident.
        // CreatePlacedResource will fail if it is not.
        Heap* heap = static_cast<Heap*>(subAllocation.GetMemory());
        ASSERT(heap != nullptr);

        ComPtr<ID3D12Resource> placedResource;
        {
            // Resource is placed at an offset corresponding to the sub-allocation.
            // Each sub-allocation maps to a disjoint (physical) address range so no heap memory is
            // aliased or reused within a command-list.
            // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12device-createplacedresource
            ScopedHeapLock scopedHeapLock(GetResidencyManager(), heap);
            ReturnIfFailed(mDevice->CreatePlacedResource(
                heap->GetHeap(), subAllocation.GetOffset(), resourceDescriptor, initialUsage,
                clearValue, IID_PPV_ARGS(&placedResource)));
        }

        *resourceAllocationOut =
            new ResourceAllocation{mResidencyManager.get(), subAllocation.GetAllocator(),
                                   subAllocation.GetInfo(), std::move(placedResource), heap};

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResourceHeap(uint64_t size,
                                                  D3D12_HEAP_TYPE heapType,
                                                  D3D12_HEAP_FLAGS heapFlags,
                                                  uint64_t heapAlignment,
                                                  Heap** resourceHeapOut) {
        const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup =
            GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapType);

        // CreateHeap will implicitly make the created heap resident. We must ensure enough free
        // memory exists before allocating to avoid an out-of-memory error when overcommitted.
        if (mIsAlwaysInBudget && mResidencyManager != nullptr) {
            mResidencyManager->Evict(size, memorySegmentGroup);
        }

        D3D12_HEAP_PROPERTIES heapProperties = {};
        heapProperties.Type = heapType;
        heapProperties.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
        heapProperties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
        heapProperties.CreationNodeMask = 0;
        heapProperties.VisibleNodeMask = 0;

        D3D12_HEAP_DESC heapDesc = {};
        heapDesc.Properties = heapProperties;
        heapDesc.SizeInBytes = size;
        heapDesc.Alignment = heapAlignment;
        heapDesc.Flags = heapFlags;

        ComPtr<ID3D12Heap> d3d12Heap;
        ReturnIfFailed(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&d3d12Heap)));

        *resourceHeapOut = new Heap(std::move(d3d12Heap), memorySegmentGroup, size);

        // Calling CreateHeap implicitly calls MakeResident on the new heap. We must track this to
        // avoid calling MakeResident a second time.
        if (mResidencyManager != nullptr) {
            mResidencyManager->InsertHeap(*resourceHeapOut);
        }

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateCommittedResource(
        D3D12_HEAP_TYPE heapType,
        D3D12_HEAP_FLAGS heapFlags,
        const D3D12_RESOURCE_ALLOCATION_INFO& resourceInfo,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* clearValue,
        D3D12_RESOURCE_STATES initialUsage,
        ResourceAllocation** resourceAllocationOut) {
        if (!resourceAllocationOut) {
            return E_POINTER;
        }

        // CreateCommittedResource will implicitly make the created resource resident. We must
        // ensure enough free memory exists before allocating to avoid an out-of-memory error when
        // overcommitted.
        if (mIsAlwaysInBudget && mResidencyManager != nullptr) {
            ReturnIfFailed(mResidencyManager->Evict(
                resourceInfo.SizeInBytes,
                GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapType)));
        }

        D3D12_HEAP_PROPERTIES heapProperties;
        heapProperties.Type = heapType;
        heapProperties.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
        heapProperties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
        heapProperties.CreationNodeMask = 0;
        heapProperties.VisibleNodeMask = 0;

        // Resource heap flags must be inferred by the resource descriptor and cannot be explicitly
        // provided to CreateCommittedResource.
        heapFlags &= ~(D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES |
                       D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES | D3D12_HEAP_FLAG_DENY_BUFFERS);

        ComPtr<ID3D12Resource> committedResource;
        ReturnIfFailed(mDevice->CreateCommittedResource(
            &heapProperties, heapFlags, resourceDescriptor, initialUsage, clearValue,
            IID_PPV_ARGS(&committedResource)));

        // Since residency management occurs at the heap granularity, every committed resource is
        // wrapped in a heap object.
        Heap* resourceHeap = new Heap(
            committedResource, GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapType),
            resourceInfo.SizeInBytes);

        // Calling CreateCommittedResource implicitly calls MakeResident on the resource. We must
        // track this to avoid calling MakeResident a second time.
        if (mResidencyManager != nullptr) {
            mResidencyManager->InsertHeap(resourceHeap);
        }

        AllocationInfo info = {};
        info.mMethod = AllocationMethod::kStandalone;

        *resourceAllocationOut = new ResourceAllocation{mResidencyManager.get(),
                                                        /*allocator*/ this, info,
                                                        std::move(committedResource), resourceHeap};
        return S_OK;
    }

    void ResourceAllocator::FreeResourceHeap(Heap* resourceHeap) {
        ASSERT(resourceHeap != nullptr);
        delete resourceHeap;
    }

    ResidencyManager* ResourceAllocator::GetResidencyManager() const {
        return mResidencyManager.get();
    }

}}  // namespace gpgmm::d3d12
