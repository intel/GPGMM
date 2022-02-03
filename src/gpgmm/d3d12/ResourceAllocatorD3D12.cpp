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

#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"

#include "gpgmm/BuddyMemoryAllocator.h"
#include "gpgmm/ConditionalMemoryAllocator.h"
#include "gpgmm/SegmentedMemoryAllocator.h"
#include "gpgmm/common/Log.h"
#include "gpgmm/common/Math.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/BufferAllocatorD3D12.h"
#include "gpgmm/d3d12/DefaultsD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceHeapAllocatorD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm { namespace d3d12 {
    namespace {

        // Combines heap type and flags used to allocate memory for resources into a single type for
        // allocator lookup.
        enum RESOURCE_HEAP_TYPE {
            // Resource heap tier 2
            // Resource heaps contain all buffer and textures types.
            RESOURCE_HEAP_TYPE_READBACK_ALLOW_ALL_BUFFERS_AND_TEXTURES = 0x0,
            RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ALL_BUFFERS_AND_TEXTURES = 0x1,
            RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ALL_BUFFERS_AND_TEXTURES = 0x2,

            // Resource heap tier 1
            // Resource heaps contain buffers or textures but not both.
            RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_BUFFERS = 0x3,
            RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_BUFFERS = 0x4,
            RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_BUFFERS = 0x5,

            RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES = 0x6,
            RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES = 0x7,

            RESOURCE_HEAP_TYPE_INVALID,
        };

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
                LogMessageEvent(LogSeverity::Info, "ResourceAllocator.GetResourceAllocationInfo",
                                "D3D12 rejected the requested alignment",
                                ALLOCATOR_MESSAGE_ID_RESOURCE_ALIGNMENT_REJECTED);

                resourceDescriptor.Alignment = 0;
                resourceInfo = device->GetResourceAllocationInfo(0, 1, &resourceDescriptor);
            }

            if (resourceInfo.SizeInBytes == 0) {
                resourceInfo.SizeInBytes = kInvalidSize;
            }

            return resourceInfo;
        }

        D3D12_HEAP_TYPE GetHeapType(RESOURCE_HEAP_TYPE resourceHeapType) {
            switch (resourceHeapType) {
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                    return D3D12_HEAP_TYPE_READBACK;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES:
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES:
                    return D3D12_HEAP_TYPE_DEFAULT;
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                    return D3D12_HEAP_TYPE_UPLOAD;
                default:
                    UNREACHABLE();
                    return D3D12_HEAP_TYPE_DEFAULT;
            }
        }

        D3D12_HEAP_FLAGS GetHeapFlags(RESOURCE_HEAP_TYPE resourceHeapType) {
            switch (resourceHeapType) {
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                    return D3D12_HEAP_FLAG_ALLOW_ALL_BUFFERS_AND_TEXTURES;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_BUFFERS:
                    return D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES:
                    return D3D12_HEAP_FLAG_ALLOW_ONLY_NON_RT_DS_TEXTURES;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES:
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

        RESOURCE_HEAP_TYPE GetResourceHeapType(D3D12_RESOURCE_DIMENSION dimension,
                                               D3D12_HEAP_TYPE heapType,
                                               D3D12_RESOURCE_FLAGS flags,
                                               D3D12_RESOURCE_HEAP_TIER resourceHeapTier) {
            if (resourceHeapTier >= D3D12_RESOURCE_HEAP_TIER_2) {
                switch (heapType) {
                    case D3D12_HEAP_TYPE_UPLOAD:
                        return RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ALL_BUFFERS_AND_TEXTURES;
                    case D3D12_HEAP_TYPE_DEFAULT:
                        return RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ALL_BUFFERS_AND_TEXTURES;
                    case D3D12_HEAP_TYPE_READBACK:
                        return RESOURCE_HEAP_TYPE_READBACK_ALLOW_ALL_BUFFERS_AND_TEXTURES;
                    default:
                        UNREACHABLE();
                        return RESOURCE_HEAP_TYPE_INVALID;
                }
            }

            switch (dimension) {
                case D3D12_RESOURCE_DIMENSION_BUFFER: {
                    switch (heapType) {
                        case D3D12_HEAP_TYPE_UPLOAD:
                            return RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_BUFFERS;
                        case D3D12_HEAP_TYPE_DEFAULT:
                            return RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_BUFFERS;
                        case D3D12_HEAP_TYPE_READBACK:
                            return RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_BUFFERS;
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
                                return RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES;
                            }
                            return RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES;
                        }

                        default:
                            UNREACHABLE();
                    }
                    break;
                }
                default:
                    UNREACHABLE();
                    return RESOURCE_HEAP_TYPE_INVALID;
            }

            return RESOURCE_HEAP_TYPE_INVALID;
        }

        D3D12_RESOURCE_STATES GetInitialResourceState(D3D12_HEAP_TYPE heapType) {
            switch (heapType) {
                case D3D12_HEAP_TYPE_DEFAULT:
                case D3D12_HEAP_TYPE_UPLOAD:
                    return D3D12_RESOURCE_STATE_GENERIC_READ;
                case D3D12_HEAP_TYPE_READBACK:
                    return D3D12_RESOURCE_STATE_COPY_DEST;
                case D3D12_HEAP_TYPE_CUSTOM:
                    // TODO
                default:
                    UNREACHABLE();
            }
        }

        // RAII wrapper to lock/unlock heap from the residency cache.
        class ScopedHeapLock : public NonCopyable {
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

          private:
            ResidencyManager* const mResidencyManager;
            Heap* const mHeap;
        };

        // Combines AllocatorMemory and Create*Resource into a single call.
        // If the memory allocation was successful, the resource will be created using it.
        // Else, if the resource creation fails, the memory allocation will be cleaned up.
        template <typename CreateResourceFn>
        HRESULT TryAllocateResource(MemoryAllocator* allocator,
                                    uint64_t size,
                                    uint64_t alignment,
                                    bool neverAllocate,
                                    CreateResourceFn&& createResourceFn) {
            std::unique_ptr<MemoryAllocation> allocation =
                allocator->TryAllocateMemory(size, alignment, neverAllocate);
            if (allocation == nullptr) {
                return E_FAIL;
            }
            HRESULT hr = createResourceFn(*allocation);
            if (FAILED(hr)) {
                allocator->DeallocateMemory(allocation.release());
            }
            return hr;
        }

    }  // namespace

    // static
    HRESULT ResourceAllocator::CreateAllocator(const ALLOCATOR_DESC& descriptor,
                                               ResourceAllocator** resourceAllocatorOut,
                                               ResidencyManager** residencyManagerOut) {
        if (descriptor.Adapter == nullptr || descriptor.Device == nullptr) {
            return E_INVALIDARG;
        }

        ALLOCATOR_DESC newDescriptor = descriptor;
        newDescriptor.PreferredResourceHeapSize = (descriptor.PreferredResourceHeapSize > 0)
                                                      ? descriptor.PreferredResourceHeapSize
                                                      : kDefaultPreferredResourceHeapSize;

        newDescriptor.MaxResourceHeapSize = (descriptor.MaxResourceHeapSize > 0)
                                                ? descriptor.MaxResourceHeapSize
                                                : kDefaultMaxResourceHeapSize;

        if (newDescriptor.PreferredResourceHeapSize > newDescriptor.MaxResourceHeapSize) {
            return E_INVALIDARG;
        }

        if (newDescriptor.MaxResourceSizeForPooling > 0 &&
            newDescriptor.MaxResourceSizeForPooling > newDescriptor.MaxResourceHeapSize) {
            return E_INVALIDARG;
        }

        bool enableEventTracer =
            descriptor.RecordOptions.Flags & ALLOCATOR_RECORD_FLAG_TRACE_EVENTS;
#ifdef GPGMM_ALWAYS_RECORD
        enableEventTracer = true;
#endif

        if (enableEventTracer) {
            const std::string& traceFile = descriptor.RecordOptions.TraceFile.empty()
                                               ? std::string(kDefaultTraceFile)
                                               : descriptor.RecordOptions.TraceFile;
            const LogSeverity& recordLogLevel =
                static_cast<LogSeverity>(descriptor.RecordOptions.MinLogLevel);

            StartupEventTracer(traceFile);
            SetRecordLogLevel(recordLogLevel);
        }

        const LogSeverity& consoleEventLevel = static_cast<LogSeverity>(descriptor.MinLogLevel);
        SetLogMessageLevel(consoleEventLevel);

        ComPtr<ResidencyManager> residencyManager;
        if (SUCCEEDED(ResidencyManager::CreateResidencyManager(
                newDescriptor.Device, newDescriptor.Adapter, newDescriptor.IsUMA,
                newDescriptor.MaxVideoMemoryBudget, newDescriptor.TotalResourceBudgetLimit,
                newDescriptor.VideoMemoryEvictSize, &residencyManager))) {
        }

        *resourceAllocatorOut = new ResourceAllocator(newDescriptor, residencyManager);

        if (residencyManagerOut != nullptr) {
            *residencyManagerOut = residencyManager.Detach();
        }

        return S_OK;
    }

    ResourceAllocator::ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                                         ComPtr<ResidencyManager> residencyManager)
        : mDevice(std::move(descriptor.Device)),
          mResidencyManager(std::move(residencyManager)),
          mIsUMA(descriptor.IsUMA),
          mResourceHeapTier(descriptor.ResourceHeapTier),
          mIsAlwaysCommitted(descriptor.Flags & ALLOCATOR_FLAG_ALWAYS_COMMITED),
          mIsAlwaysInBudget(descriptor.Flags & ALLOCATOR_FLAG_ALWAYS_IN_BUDGET),
          mMaxResourceHeapSize(descriptor.MaxResourceHeapSize) {
        LogEvent("GPUMemoryAllocator", descriptor);
        TRACE_EVENT_OBJECT_CREATED_WITH_ID("GPUMemoryAllocator", this);

        for (uint32_t resourceHeapTypeIndex = 0; resourceHeapTypeIndex < kNumOfResourceHeapTypes;
             resourceHeapTypeIndex++) {
            const RESOURCE_HEAP_TYPE resourceHeapType =
                static_cast<RESOURCE_HEAP_TYPE>(resourceHeapTypeIndex);

            const D3D12_HEAP_FLAGS& heapFlags = GetHeapFlags(resourceHeapType);
            const uint64_t& heapAlignment = GetHeapAlignment(heapFlags);
            const D3D12_HEAP_TYPE& heapType = GetHeapType(resourceHeapType);

            {
                std::unique_ptr<MemoryAllocator> standaloneAllocator =
                    std::make_unique<ResourceHeapAllocator>(this, heapType, heapFlags);

                std::unique_ptr<MemoryAllocator> pooledHeapAllocator =
                    std::make_unique<SegmentedMemoryAllocator>(
                        std::make_unique<ResourceHeapAllocator>(this, heapType, heapFlags),
                        heapAlignment);

                std::unique_ptr<MemoryAllocator> conditionalHeapAllocator =
                    std::make_unique<ConditionalMemoryAllocator>(
                        std::move(pooledHeapAllocator), std::move(standaloneAllocator),
                        descriptor.MaxResourceSizeForPooling);

                mResourceSubAllocatorOfType[resourceHeapTypeIndex] =
                    std::make_unique<BuddyMemoryAllocator>(
                        mMaxResourceHeapSize, descriptor.PreferredResourceHeapSize, heapAlignment,
                        std::move(conditionalHeapAllocator));
            }

            {
                std::unique_ptr<MemoryAllocator> standaloneAllocator =
                    std::make_unique<ResourceHeapAllocator>(this, heapType, heapFlags);

                std::unique_ptr<MemoryAllocator> pooledHeapAllocator =
                    std::make_unique<SegmentedMemoryAllocator>(
                        std::make_unique<ResourceHeapAllocator>(this, heapType, heapFlags),
                        heapAlignment);

                mResourceHeapAllocatorOfType[resourceHeapTypeIndex] =
                    std::make_unique<ConditionalMemoryAllocator>(
                        std::move(pooledHeapAllocator), std::move(standaloneAllocator),
                        descriptor.MaxResourceSizeForPooling);
            }

            {
                std::unique_ptr<MemoryAllocator> bufferAllocator =
                    std::make_unique<BufferAllocator>(
                        this, heapType, D3D12_RESOURCE_FLAG_NONE, GetInitialResourceState(heapType),
                        /*resourceSize*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*resourceAlignment*/ 0);

                std::unique_ptr<BuddyMemoryAllocator> bufferSubAllocator =
                    std::make_unique<BuddyMemoryAllocator>(
                        mMaxResourceHeapSize,
                        /*resourceSize*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*resourceAlignment*/ 0, std::move(bufferAllocator));

                mBufferSubAllocatorOfType[resourceHeapTypeIndex] = std::move(bufferSubAllocator);
            }
        }
    }

    ResourceAllocator::~ResourceAllocator() {
        TRACE_EVENT_OBJECT_DELETED_WITH_ID("GPUMemoryAllocator", this);

        // Destroy allocators in the reverse order they were created so we can record delete events
        // before event tracer shutdown.
        mBufferSubAllocatorOfType = {};
        mResourceSubAllocatorOfType = {};
        mResourceHeapAllocatorOfType = {};

        ShutdownEventTracer();
    }

    void ResourceAllocator::Trim() {
        for (auto& allocator : mResourceHeapAllocatorOfType) {
            ASSERT(allocator != nullptr);
            allocator->ReleaseMemory();
        }
    }

    HRESULT ResourceAllocator::CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                              const D3D12_RESOURCE_DESC& resourceDescriptor,
                                              D3D12_RESOURCE_STATES initialResourceState,
                                              const D3D12_CLEAR_VALUE* clearValue,
                                              ResourceAllocation** resourceAllocationOut) {
        if (!resourceAllocationOut) {
            return E_POINTER;
        }

        LogEvent<CREATE_RESOURCE_DESC>("ResourceAllocator.CreateResource", allocationDescriptor,
                                       resourceDescriptor, initialResourceState, clearValue);

        TRACE_EVENT_CALL_SCOPED("ResourceAllocator.CreateResource");

        // If d3d tells us the resource size is invalid, treat the error as OOM.
        // Otherwise, creating a very large resource could overflow the allocator.
        D3D12_RESOURCE_DESC newResourceDesc = resourceDescriptor;
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), newResourceDesc);
        if (resourceInfo.SizeInBytes == kInvalidSize) {
            return E_OUTOFMEMORY;
        }

        if (resourceInfo.SizeInBytes > mMaxResourceHeapSize) {
            return E_OUTOFMEMORY;
        }

        const RESOURCE_HEAP_TYPE resourceHeapType =
            GetResourceHeapType(newResourceDesc.Dimension, allocationDescriptor.HeapType,
                                newResourceDesc.Flags, mResourceHeapTier);

        if (resourceInfo.SizeInBytes < resourceInfo.Alignment) {
            LogMessageEvent(LogSeverity::Info, "ResourceAllocator.CreateResource",
                            "Resource size is smaller then the alignment.",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_SUBOPTIMAL_ALIGNMENT);
        }

        const bool neverAllocate =
            allocationDescriptor.Flags & ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;

        const bool neverSubAllocate =
            allocationDescriptor.Flags & ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;

        // Attempt to allocate using the most effective allocator.
        bool didTrySubAllocate = false;
        MemoryAllocator* allocator = nullptr;

        // Attempt to create a resource allocation within the same resource.
        // This has the same performace as sub-allocating resource heaps without the
        // drawback of requiring resource heaps to be 64KB size-aligned. However, this
        // strategy only works in a few cases (ex. small constant buffers uploads) so it should be
        // tried before sub-allocating resource heaps.
        // The time and space complexity of is defined by the sub-allocation algorithm used.
        if ((allocationDescriptor.Flags & ALLOCATION_FLAG_SUBALLOCATE_WITHIN_RESOURCE) &&
            resourceInfo.Alignment > resourceDescriptor.Width &&
            resourceDescriptor.Dimension == D3D12_RESOURCE_DIMENSION_BUFFER &&
            GetInitialResourceState(GetHeapType(resourceHeapType)) == initialResourceState &&
            !mIsAlwaysCommitted && !neverSubAllocate) {
            allocator = mBufferSubAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();

            const uint64_t subAllocatedAlignment =
                (resourceDescriptor.Alignment == 0) ? 1 : resourceDescriptor.Alignment;

            ReturnIfSucceeded(TryAllocateResource(
                allocator, resourceDescriptor.Width, subAllocatedAlignment, neverAllocate,
                [&](const auto& subAllocation) -> HRESULT {
                    // Committed resource implicitly creates a resource heap which can be
                    // used for sub-allocation.
                    ComPtr<ID3D12Resource> committedResource;
                    Heap* resourceHeap = ToBackendType(subAllocation.GetMemory());
                    ReturnIfFailed(resourceHeap->GetPageable().As(&committedResource));

                    *resourceAllocationOut = new ResourceAllocation{
                        mResidencyManager.Get(),      subAllocation.GetAllocator(),
                        subAllocation.GetBlock(),     subAllocation.GetOffset(),
                        std::move(committedResource), resourceHeap};

                    if (subAllocation.GetSize() > resourceDescriptor.Width) {
                        LogMessageEvent(
                            LogSeverity::Info, "ResourceAllocator.CreateResource",
                            "Resource allocation size is larger then the resource size.",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_SUBOPTIONAL_ALIGNMENT);
                    }

                    return S_OK;
                }));

            didTrySubAllocate = true;
        }

        // Attempt to create a resource allocation by placing a resource in a sub-allocated
        // resource heap.
        // The time and space complexity of is determined by the sub-allocation algorithm used.
        if (!mIsAlwaysCommitted && !neverSubAllocate) {
            allocator = mResourceSubAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();

            ReturnIfSucceeded(TryAllocateResource(
                allocator, resourceInfo.SizeInBytes, resourceInfo.Alignment, neverAllocate,
                [&](const auto& subAllocation) -> HRESULT {
                    // Resource is placed at an offset corresponding to the allocation offset.
                    // Each allocation maps to a disjoint (physical) address range so no physical
                    // memory is can be aliased or will overlap.
                    ComPtr<ID3D12Resource> placedResource;
                    Heap* resourceHeap = ToBackendType(subAllocation.GetMemory());
                    ReturnIfFailed(CreatePlacedResource(resourceHeap, subAllocation.GetOffset(),
                                                        &newResourceDesc, clearValue,
                                                        initialResourceState, &placedResource));

                    *resourceAllocationOut = new ResourceAllocation{
                        mResidencyManager.Get(),   subAllocation.GetAllocator(),
                        subAllocation.GetOffset(), subAllocation.GetBlock(),
                        std::move(placedResource), resourceHeap};

                    if (subAllocation.GetSize() > resourceInfo.SizeInBytes) {
                        LogMessageEvent(
                            LogSeverity::Info, "ResourceAllocator.CreateResource",
                            "Resource allocation size is larger then the resource size.",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_SUBOPTIONAL_ALIGNMENT);
                    }

                    return S_OK;
                }));

            didTrySubAllocate = true;
        }

        if (didTrySubAllocate) {
            LogMessageEvent(LogSeverity::Info, "ResourceAllocator.CreateResource",
                            "Suballocation was attempted but failed.",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_SUBALLOCATION_FAILED);
        }

        // Attempt to create a resource allocation by placing a single resource fully contained
        // in a resource heap. This strategy is slightly better then creating a committed
        // resource because a placed resource's heap will not be reallocated by the OS until Trim()
        // is called.
        // The time and space complexity is determined by the allocator type.
        if (!mIsAlwaysCommitted) {
            allocator = mResourceHeapAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();

            // Resource alignment should be equal to or greater then the heap alignment to avoid
            // fragmenting the OS VidMM.
            const D3D12_HEAP_FLAGS heapFlags = GetHeapFlags(resourceHeapType);
            const uint64_t heapAlignment = GetHeapAlignment(heapFlags);
            const uint64_t heapSize = resourceInfo.SizeInBytes;

            ReturnIfSucceeded(TryAllocateResource(
                allocator, heapSize, heapAlignment, neverAllocate,
                [&](const auto& allocation) -> HRESULT {
                    // If the resource's heap cannot be pooled then it is no better then
                    // calling CreateCommittedResource if the allocation is not fully contained.
                    Heap* resourceHeap = ToBackendType(allocation.GetMemory());
                    if (resourceHeap->GetPool() == nullptr &&
                        allocation.GetSize() % heapSize != 0) {
                        return E_FAIL;
                    }

                    ComPtr<ID3D12Resource> placedResource;
                    ReturnIfFailed(CreatePlacedResource(resourceHeap, allocation.GetOffset(),
                                                        &newResourceDesc, clearValue,
                                                        initialResourceState, &placedResource));

                    *resourceAllocationOut =
                        new ResourceAllocation{mResidencyManager.Get(), allocation.GetAllocator(),
                                               std::move(placedResource), resourceHeap};

                    if (allocation.GetSize() > heapSize) {
                        LogMessageEvent(
                            LogSeverity::Info, "ResourceAllocator.CreateResource",
                            "Resource allocation size is larger then the resource size.",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_SUBOPTIONAL_ALIGNMENT);
                    }

                    return S_OK;
                }));
        }

        // Attempt to create a standalone committed resource. This strategy is the safest but also
        // the most expensive so it's used as a last resort or if the developer needs larger
        // allocations where sub-allocation or pooling is otherwise ineffective.
        // The time and space complexity of committed resource is driver-defined.
        if (neverAllocate) {
            return E_OUTOFMEMORY;
        }

        if (!mIsAlwaysCommitted) {
            LogMessageEvent(LogSeverity::Info, "ResourceAllocator.CreateResource",
                            "Resource allocation could not be created from memory pool.",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_NON_POOLED);
        }

        ComPtr<ID3D12Resource> committedResource;
        Heap* resourceHeap = nullptr;
        ReturnIfFailed(CreateCommittedResource(
            allocationDescriptor.HeapType, GetHeapFlags(resourceHeapType), resourceInfo.SizeInBytes,
            &newResourceDesc, clearValue, initialResourceState, &committedResource, &resourceHeap));

        *resourceAllocationOut = new ResourceAllocation{mResidencyManager.Get(), this,
                                                        std::move(committedResource), resourceHeap};

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResource(ComPtr<ID3D12Resource> resource,
                                              ResourceAllocation** resourceAllocationOut) {
        if (!resourceAllocationOut) {
            return E_POINTER;
        }

        if (resource == nullptr) {
            return E_INVALIDARG;
        }

        D3D12_RESOURCE_DESC desc = resource->GetDesc();
        LogEvent("ResourceAllocator.CreateResource", desc);
        TRACE_EVENT_CALL_SCOPED("ResourceAllocator.CreateResource");

        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), desc);

        D3D12_HEAP_PROPERTIES heapProperties;
        ReturnIfFailed(resource->GetHeapProperties(&heapProperties, nullptr));

        Heap* resourceHeap = new Heap(
            resource, GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapProperties.Type),
            resourceInfo.SizeInBytes);

        *resourceAllocationOut =
            new ResourceAllocation{/*residencyManager*/ nullptr,
                                   /*allocator*/ this, std::move(resource), resourceHeap};

        return S_OK;
    }

    HRESULT ResourceAllocator::CreatePlacedResource(Heap* const resourceHeap,
                                                    uint64_t resourceOffset,
                                                    const D3D12_RESOURCE_DESC* resourceDescriptor,
                                                    const D3D12_CLEAR_VALUE* clearValue,
                                                    D3D12_RESOURCE_STATES initialResourceState,
                                                    ID3D12Resource** placedResourceOut) {
        if (resourceHeap == nullptr) {
            return E_FAIL;
        }

        // Before calling CreatePlacedResource, we must ensure the target heap is resident or
        // CreatePlacedResource will fail.
        ComPtr<ID3D12Resource> placedResource;
        {
            ScopedHeapLock scopedHeapLock(mResidencyManager.Get(), resourceHeap);
            ReturnIfFailed(mDevice->CreatePlacedResource(
                resourceHeap->GetHeap(), resourceOffset, resourceDescriptor, initialResourceState,
                clearValue, IID_PPV_ARGS(&placedResource)));
        }

        *placedResourceOut = placedResource.Detach();

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResourceHeap(uint64_t heapSize,
                                                  D3D12_HEAP_TYPE heapType,
                                                  D3D12_HEAP_FLAGS heapFlags,
                                                  uint64_t heapAlignment,
                                                  Heap** resourceHeapOut) {
        TRACE_EVENT_CALL_SCOPED("ResourceAllocator.CreateResourceHeap");

        const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup =
            GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapType);

        // CreateHeap will implicitly make the created heap resident. We must ensure enough free
        // memory exists before allocating to avoid an out-of-memory error when overcommitted.
        if (mIsAlwaysInBudget && mResidencyManager != nullptr) {
            mResidencyManager->Evict(heapSize, memorySegmentGroup);
        }

        D3D12_HEAP_PROPERTIES heapProperties = {};
        heapProperties.Type = heapType;

        D3D12_HEAP_DESC heapDesc = {};
        heapDesc.Properties = heapProperties;
        heapDesc.SizeInBytes = heapSize;
        heapDesc.Alignment = heapAlignment;
        heapDesc.Flags = heapFlags;

        if (heapSize % heapAlignment != 0) {
            LogMessageEvent(LogSeverity::Info, "ResourceAllocator.CreateResourceHeap",
                            "Heap size is not a multiple of the alignment.",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_HEAP_SUBOPTIMAL_ALIGNMENT);
        }

        ComPtr<ID3D12Heap> heap;
        ReturnIfFailed(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap)));

        Heap* resourceHeap = new Heap(std::move(heap), memorySegmentGroup, heapSize);

        // Calling CreateHeap implicitly calls MakeResident on the new heap. We must track this to
        // avoid calling MakeResident a second time.
        if (mResidencyManager != nullptr) {
            mResidencyManager->InsertHeap(resourceHeap);
        }

        *resourceHeapOut = resourceHeap;

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateCommittedResource(
        D3D12_HEAP_TYPE heapType,
        D3D12_HEAP_FLAGS heapFlags,
        uint64_t resourceSize,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* clearValue,
        D3D12_RESOURCE_STATES initialResourceState,
        ID3D12Resource** commitedResourceOut,
        Heap** resourceHeapOut) {
        TRACE_EVENT_CALL_SCOPED("ResourceAllocator.CreateCommittedResource");

        // CreateCommittedResource will implicitly make the created resource resident. We must
        // ensure enough free memory exists before allocating to avoid an out-of-memory error when
        // overcommitted.
        const DXGI_MEMORY_SEGMENT_GROUP memorySegmentGroup =
            GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapType);

        if (mIsAlwaysInBudget && mResidencyManager != nullptr) {
            ReturnIfFailed(mResidencyManager->Evict(resourceSize, memorySegmentGroup));
        }

        D3D12_HEAP_PROPERTIES heapProperties = {};
        heapProperties.Type = heapType;

        // Resource heap flags must be inferred by the resource descriptor and cannot be explicitly
        // provided to CreateCommittedResource.
        heapFlags &= ~(D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES |
                       D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES | D3D12_HEAP_FLAG_DENY_BUFFERS);

        ComPtr<ID3D12Resource> committedResource;
        ReturnIfFailed(mDevice->CreateCommittedResource(
            &heapProperties, heapFlags, resourceDescriptor, initialResourceState, clearValue,
            IID_PPV_ARGS(&committedResource)));

        // Since residency is per heap, every committed resource is wrapped in a heap object.
        Heap* resourceHeap = new Heap(committedResource, memorySegmentGroup, resourceSize);

        // Calling CreateCommittedResource implicitly calls MakeResident on the resource. We must
        // track this to avoid calling MakeResident a second time.
        if (mResidencyManager != nullptr) {
            mResidencyManager->InsertHeap(resourceHeap);
        }

        if (commitedResourceOut != nullptr) {
            *commitedResourceOut = committedResource.Detach();
        }

        *resourceHeapOut = resourceHeap;

        return S_OK;
    }

    void ResourceAllocator::FreeResourceHeap(Heap* resourceHeap) {
        ASSERT(resourceHeap != nullptr);
        ASSERT(resourceHeap->RefCount() == 0);

        delete resourceHeap;
    }

    ResidencyManager* ResourceAllocator::GetResidencyManager() const {
        return mResidencyManager.Get();
    }

    HRESULT ResourceAllocator::QueryResourceAllocatorInfo(
        QUERY_RESOURCE_ALLOCATOR_INFO* resorceAllocationInfoOut) const {
        QUERY_RESOURCE_ALLOCATOR_INFO infoOut = {};
        for (auto& allocator : mResourceSubAllocatorOfType) {
            const MEMORY_ALLOCATOR_INFO& info = allocator->QueryInfo();
            infoOut.UsedBlockCount += info.UsedBlockCount;
            infoOut.UsedBlockUsage += info.UsedBlockUsage;
            infoOut.UsedResourceHeapUsage += info.UsedMemoryUsage;
            infoOut.UsedResourceHeapCount += info.UsedMemoryCount;
        }

        for (auto& allocator : mResourceHeapAllocatorOfType) {
            const MEMORY_ALLOCATOR_INFO& info = allocator->QueryInfo();
            infoOut.UsedResourceHeapUsage += info.UsedMemoryUsage;
            infoOut.UsedResourceHeapCount += info.UsedMemoryCount;
        }

        for (auto& allocator : mBufferSubAllocatorOfType) {
            const MEMORY_ALLOCATOR_INFO& info = allocator->QueryInfo();
            infoOut.UsedResourceHeapCount += info.UsedMemoryCount;
            infoOut.UsedResourceHeapUsage += info.UsedMemoryUsage;
            infoOut.UsedBlockCount += info.UsedBlockCount;
            infoOut.UsedBlockUsage += info.UsedBlockUsage;
        }

        d3d12::LogObject("GPUMemoryAllocator", this, infoOut);

        if (resorceAllocationInfoOut != nullptr) {
            *resorceAllocationInfoOut = infoOut;
        }

        return S_OK;
    }

}}  // namespace gpgmm::d3d12
