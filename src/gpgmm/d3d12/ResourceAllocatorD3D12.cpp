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

#include "gpgmm/common/BuddyMemoryAllocator.h"
#include "gpgmm/common/Defaults.h"
#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/PooledMemoryAllocator.h"
#include "gpgmm/common/SegmentedMemoryAllocator.h"
#include "gpgmm/common/SlabMemoryAllocator.h"
#include "gpgmm/common/StandaloneMemoryAllocator.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/BufferAllocatorD3D12.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/DebugResourceAllocatorD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceHeapAllocatorD3D12.h"
#include "gpgmm/d3d12/ResourceSizeD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm::d3d12 {
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

        D3D12_RESOURCE_ALLOCATION_INFO GetResourceAllocationInfo(
            ID3D12Device* device,
            D3D12_RESOURCE_DESC& resourceDescriptor) {
            // Small textures can take advantage of smaller alignments. For example,
            // if the most detailed mip can fit under 64KB, 4KB alignments can be used.
            // Must be non-depth or without render-target to use small resource alignment.
            // This also applies to MSAA textures (4MB => 64KB).
            // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_resource_desc
            if ((resourceDescriptor.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE1D ||
                 resourceDescriptor.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE2D ||
                 resourceDescriptor.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE3D) &&
                IsAllowedToUseSmallAlignment(resourceDescriptor) &&
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
                DebugLog() << "ID3D12Device::GetResourceAllocationInfo re-aligned (" +
                                  std::to_string(resourceDescriptor.Alignment) + " vs " +
                                  std::to_string(resourceInfo.Alignment) + " bytes)";

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

        D3D12_HEAP_FLAGS GetHeapFlags(RESOURCE_HEAP_TYPE resourceHeapType, bool createNotResident) {
            const D3D12_HEAP_FLAGS createHeapFlags =
                (createNotResident) ? D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT : D3D12_HEAP_FLAG_NONE;
            switch (resourceHeapType) {
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                    return createHeapFlags | D3D12_HEAP_FLAG_ALLOW_ALL_BUFFERS_AND_TEXTURES;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_BUFFERS:
                    return createHeapFlags | D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES:
                    return createHeapFlags | D3D12_HEAP_FLAG_ALLOW_ONLY_NON_RT_DS_TEXTURES;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES:
                    return createHeapFlags | D3D12_HEAP_FLAG_ALLOW_ONLY_RT_DS_TEXTURES;
                default:
                    UNREACHABLE();
                    return D3D12_HEAP_FLAG_NONE;
            }
        }

        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_flags
        uint64_t GetHeapAlignment(D3D12_HEAP_FLAGS heapFlags, bool allowMSAA) {
            const D3D12_HEAP_FLAGS denyAllTexturesFlags =
                D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES | D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES;
            if (Flags(heapFlags).HasFlags(denyAllTexturesFlags)) {
                return D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT;
            }

            if (allowMSAA) {
                return D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT;
            }

            return D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT;
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
                    case D3D12_HEAP_TYPE_CUSTOM:
                    default:
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
                        case D3D12_HEAP_TYPE_CUSTOM:
                        default:
                            return RESOURCE_HEAP_TYPE_INVALID;
                    }
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
                            return RESOURCE_HEAP_TYPE_INVALID;
                    }
                }
                default:
                    return RESOURCE_HEAP_TYPE_INVALID;
            }
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
        class ScopedResidencyLock final : public NonCopyable {
          public:
            ScopedResidencyLock(ResidencyManager* const residencyManager, Heap* const heap)
                : mResidencyManager(residencyManager), mHeap(heap) {
                ASSERT(heap != nullptr);
                if (mResidencyManager != nullptr) {
                    mResidencyManager->LockHeap(mHeap);
                }
            }

            ~ScopedResidencyLock() {
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
        HRESULT TryAllocateResource(ID3D12Device* device,
                                    MemoryAllocator* allocator,
                                    const MemoryAllocationRequest& request,
                                    CreateResourceFn&& createResourceFn) {
            std::unique_ptr<MemoryAllocation> allocation = allocator->TryAllocateMemory(request);
            if (allocation == nullptr) {
                // NeverAllocate always fails, so suppress it.
                if (!request.NeverAllocate) {
                    DebugEvent(allocator->GetTypename(), EventMessageId::AllocatorFailed)
                        << "Unable to allocate memory for request.";
                }
                return E_FAIL;
            }

            HRESULT hr = createResourceFn(*allocation);
            if (FAILED(hr)) {
                InfoEvent(allocator->GetTypename(), EventMessageId::AllocatorFailed)
                    << "Failed to create resource using allocation: " +
                           GetDeviceErrorMessage(device, hr);
                allocator->DeallocateMemory(std::move(allocation));
            }
            return hr;
        }

    }  // namespace

    // static
    HRESULT ResourceAllocator::CreateAllocator(const ALLOCATOR_DESC& allocatorDescriptor,
                                               ResourceAllocator** ppResourceAllocatorOut,
                                               ResidencyManager** ppResidencyManagerOut) {
        if (allocatorDescriptor.Device == nullptr || allocatorDescriptor.Adapter == nullptr) {
            return E_INVALIDARG;
        }

        ComPtr<ResidencyManager> residencyManager;
        if (ppResidencyManagerOut != nullptr) {
            RESIDENCY_DESC residencyDesc = {};
            residencyDesc.Device = allocatorDescriptor.Device;

            D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
            ReturnIfFailed(residencyDesc.Device->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE,
                                                                     &arch, sizeof(arch)));
            residencyDesc.IsUMA = arch.UMA;

            residencyDesc.MinLogLevel = allocatorDescriptor.MinLogLevel;
            residencyDesc.RecordOptions = allocatorDescriptor.RecordOptions;
            ReturnIfFailed(allocatorDescriptor.Adapter.As(&residencyDesc.Adapter));

            ReturnIfFailed(
                ResidencyManager::CreateResidencyManager(residencyDesc, &residencyManager));
        }

        ComPtr<ResourceAllocator> resourceAllocator;
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
        if (allocatorDescriptor.Adapter == nullptr || allocatorDescriptor.Device == nullptr) {
            return E_INVALIDARG;
        }

        std::unique_ptr<Caps> caps;
        {
            Caps* ptr = nullptr;
            ReturnIfFailed(Caps::CreateCaps(allocatorDescriptor.Device.Get(),
                                            allocatorDescriptor.Adapter.Get(), &ptr));
            caps.reset(ptr);
        }

        ALLOCATOR_DESC newDescriptor = allocatorDescriptor;
        newDescriptor.MemoryGrowthFactor = (allocatorDescriptor.MemoryGrowthFactor >= 1.0)
                                               ? allocatorDescriptor.MemoryGrowthFactor
                                               : kDefaultMemoryGrowthFactor;

        // ID3D12Device::CreateCommittedResource and ID3D12Device::CreateHeap implicity
        // call ID3D12Device::MakeResident, requiring resource heaps to be "created in budget".
        // But this can be disabled if D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT is supported.
        if (!(allocatorDescriptor.Flags & ALLOCATOR_FLAG_ALWAYS_IN_BUDGET) &&
            !caps->IsCreateHeapNotResidentSupported()) {
            newDescriptor.Flags |= ALLOCATOR_FLAG_ALWAYS_IN_BUDGET;
        }

        newDescriptor.MaxResourceHeapSize =
            (allocatorDescriptor.MaxResourceHeapSize > 0)
                ? std::min(allocatorDescriptor.MaxResourceHeapSize, caps->GetMaxResourceHeapSize())
                : caps->GetMaxResourceHeapSize();

        newDescriptor.MemoryFragmentationLimit = (allocatorDescriptor.MemoryFragmentationLimit > 0)
                                                     ? allocatorDescriptor.MemoryFragmentationLimit
                                                     : kDefaultFragmentationLimit;

        if (newDescriptor.PreferredResourceHeapSize > newDescriptor.MaxResourceHeapSize) {
            return E_INVALIDARG;
        }

        if (pResidencyManager == nullptr &&
            newDescriptor.RecordOptions.Flags != EVENT_RECORD_FLAG_NONE) {
            StartupEventTrace(allocatorDescriptor.RecordOptions.TraceFile,
                              static_cast<TraceEventPhase>(~newDescriptor.RecordOptions.Flags | 0));

            SetEventMessageLevel(GetLogSeverity(newDescriptor.RecordOptions.MinMessageLevel));
        } else {
            // Do not override the event scope from a event trace already enabled.
            newDescriptor.RecordOptions.EventScope = EVENT_RECORD_SCOPE_PER_PROCESS;
        }

        // Do not override the default min. log level specified by the residency manager.
        // Only if this allocator is without residency, does the min. log level have affect.
        if (pResidencyManager == nullptr) {
            SetLogMessageLevel(GetLogSeverity(newDescriptor.MinLogLevel));
        }

#if defined(GPGMM_ENABLE_DEVICE_LEAK_CHECKS)
        ComPtr<ID3D12InfoQueue> leakMessageQueue;
        if (SUCCEEDED(newDescriptor.Device.As(&leakMessageQueue))) {
            D3D12_INFO_QUEUE_FILTER emptyFilter{};
            ReturnIfFailed(leakMessageQueue->PushRetrievalFilter(&emptyFilter));
        } else {
            gpgmm::WarningLog() << "Debug layer must be installed and enabled to use "
                                   "GPGMM_ENABLE_DEVICE_LEAK_CHECKS.";
        }
#endif

        if (newDescriptor.Flags & ALLOCATOR_FLAG_ALWAYS_IN_BUDGET && !pResidencyManager) {
            gpgmm::WarningLog() << "Residency must be specified and enabled to use "
                                   "ALLOCATOR_FLAG_ALWAYS_IN_BUDGET.";
        }

        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(*ppResourceAllocatorOut, newDescriptor);

        if (ppResourceAllocatorOut != nullptr) {
            *ppResourceAllocatorOut =
                new ResourceAllocator(newDescriptor, pResidencyManager, std::move(caps));
        }

        return S_OK;
    }

    ResourceAllocator::ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                                         ComPtr<ResidencyManager> residencyManager,
                                         std::unique_ptr<Caps> caps)
        : mDevice(std::move(descriptor.Device)),
          mResidencyManager(std::move(residencyManager)),
          mCaps(std::move(caps)),
          mResourceHeapTier(descriptor.ResourceHeapTier),
          mIsAlwaysCommitted(descriptor.Flags & ALLOCATOR_FLAG_ALWAYS_COMMITED),
          mIsAlwaysInBudget(descriptor.Flags & ALLOCATOR_FLAG_ALWAYS_IN_BUDGET),
          mFlushEventBuffersOnDestruct(descriptor.RecordOptions.EventScope &
                                       EVENT_RECORD_SCOPE_PER_INSTANCE),
          mUseDetailedTimingEvents(descriptor.RecordOptions.UseDetailedTimingEvents) {
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);

#if defined(GPGMM_ENABLE_ALLOCATOR_LEAK_CHECKS)
        mDebugAllocator = std::make_unique<DebugResourceAllocator>();
#endif

        for (uint32_t resourceHeapTypeIndex = 0; resourceHeapTypeIndex < kNumOfResourceHeapTypes;
             resourceHeapTypeIndex++) {
            const RESOURCE_HEAP_TYPE& resourceHeapType =
                static_cast<RESOURCE_HEAP_TYPE>(resourceHeapTypeIndex);

            const D3D12_HEAP_FLAGS& heapFlags =
                GetHeapFlags(resourceHeapType, IsCreateHeapNotResident());
            const D3D12_HEAP_TYPE& heapType = GetHeapType(resourceHeapType);

            const uint64_t msaaHeapAlignment = GetHeapAlignment(heapFlags, true);
            const uint64_t heapAlignment = GetHeapAlignment(heapFlags, false);

            // General-purpose allocators.
            // Used for dynamic resource allocation or when the resource size is not known at
            // compile-time.
            mResourceAllocatorOfType[resourceHeapTypeIndex] =
                CreateResourceSubAllocator(descriptor, heapFlags, heapType, heapAlignment);

            mMSAAResourceAllocatorOfType[resourceHeapTypeIndex] =
                CreateResourceSubAllocator(descriptor, heapFlags, heapType, msaaHeapAlignment);

            mResourceHeapAllocatorOfType[resourceHeapTypeIndex] =
                CreateResourceHeapAllocator(descriptor, heapFlags, heapType, heapAlignment);

            mMSAAResourceHeapAllocatorOfType[resourceHeapTypeIndex] =
                CreateResourceHeapAllocator(descriptor, heapFlags, heapType, msaaHeapAlignment);

            // Resource specific allocators.
            mSmallBufferAllocatorOfType[resourceHeapTypeIndex] =
                CreateSmallBufferAllocator(descriptor, heapFlags, heapType, heapAlignment);

            // Cache resource sizes commonly requested.
            // Allows the next memory block to be made available upon request without
            // increasing memory footprint. Since resources are always sized-aligned, the
            // cached size must be requested per alignment {4KB, 64KB, or 4MB}. To avoid unbounded
            // cache growth, a known set of pre-defined sizes initializes the allocators.
#if !defined(GPGMM_DISABLE_SIZE_CACHE)
            {
                // Temporary suppress log messages emitted from internal cache-miss requests.
                ScopedLogLevel scopedLogLevel(LogSeverity::Info);

                MemoryAllocationRequest cacheRequest = {};
                cacheRequest.NeverAllocate = true;
                cacheRequest.AlwaysCacheSize = true;
                cacheRequest.AlwaysPrefetch = false;
                cacheRequest.AvailableForAllocation = kInvalidSize;

                for (const SizeClassInfo& sizeInfo : ResourceSize::GenerateAllClassSizes()) {
                    MemoryAllocator* allocator = nullptr;
                    cacheRequest.SizeInBytes = sizeInfo.SizeInBytes;
                    cacheRequest.Alignment = sizeInfo.Alignment;

                    allocator = mSmallBufferAllocatorOfType[resourceHeapTypeIndex].get();
                    if (cacheRequest.SizeInBytes <= allocator->GetMemorySize() &&
                        sizeInfo.Alignment == D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT) {
                        allocator->TryAllocateMemory(cacheRequest);
                    }

                    allocator = mResourceAllocatorOfType[resourceHeapTypeIndex].get();
                    if (cacheRequest.SizeInBytes <= allocator->GetMemorySize() &&
                        sizeInfo.Alignment == D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT) {
                        allocator->TryAllocateMemory(cacheRequest);
                    }

                    allocator = mMSAAResourceAllocatorOfType[resourceHeapTypeIndex].get();
                    if (cacheRequest.SizeInBytes <= allocator->GetMemorySize() &&
                        sizeInfo.Alignment == D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT) {
                        allocator->TryAllocateMemory(cacheRequest);
                    }
                }
            }
#endif  // !defined(GPGMM_DISABLE_SIZE_CACHE)
        }
    }

    std::unique_ptr<MemoryAllocator> ResourceAllocator::CreateResourceSubAllocator(
        const ALLOCATOR_DESC& descriptor,
        D3D12_HEAP_FLAGS heapFlags,
        D3D12_HEAP_TYPE heapType,
        uint64_t heapAlignment) {
        std::unique_ptr<MemoryAllocator> pooledOrNonPooledAllocator =
            CreateResourceHeapAllocator(descriptor, heapFlags, heapType, heapAlignment);

        const uint64_t maxResourceHeapSize = mCaps->GetMaxResourceHeapSize();
        switch (descriptor.SubAllocationAlgorithm) {
            case ALLOCATOR_ALGORITHM_BUDDY_SYSTEM: {
                return std::make_unique<BuddyMemoryAllocator>(
                    /*systemSize*/ PrevPowerOfTwo(maxResourceHeapSize),
                    /*memorySize*/ std::max(heapAlignment, descriptor.PreferredResourceHeapSize),
                    /*memoryAlignment*/ heapAlignment,
                    /*memoryAllocator*/ std::move(pooledOrNonPooledAllocator));
            }
            case ALLOCATOR_ALGORITHM_SLAB: {
                return std::make_unique<SlabCacheAllocator>(
                    /*maxSlabSize*/ PrevPowerOfTwo(maxResourceHeapSize),
                    /*minSlabSize*/ std::max(heapAlignment, descriptor.PreferredResourceHeapSize),
                    /*slabAlignment*/ heapAlignment,
                    /*slabFragmentationLimit*/ descriptor.MemoryFragmentationLimit,
                    /*allowSlabPrefetch*/
                    !(descriptor.Flags & ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH),
                    /*slabGrowthFactor*/ descriptor.MemoryGrowthFactor,
                    /*memoryAllocator*/ std::move(pooledOrNonPooledAllocator));
            }
            default: {
                UNREACHABLE();
                return {};
            }
        }
    }

    std::unique_ptr<MemoryAllocator> ResourceAllocator::CreateResourceHeapAllocator(
        const ALLOCATOR_DESC& descriptor,
        D3D12_HEAP_FLAGS heapFlags,
        D3D12_HEAP_TYPE heapType,
        uint64_t heapAlignment) {
        std::unique_ptr<MemoryAllocator> resourceHeapAllocator =
            std::make_unique<ResourceHeapAllocator>(mResidencyManager.Get(), mDevice.Get(),
                                                    heapType, heapFlags, mIsAlwaysInBudget);

        if (!(descriptor.Flags & ALLOCATOR_FLAG_ALWAYS_ON_DEMAND)) {
            switch (descriptor.PoolAlgorithm) {
                case ALLOCATOR_ALGORITHM_FIXED_POOL: {
                    return std::make_unique<PooledMemoryAllocator>(
                        descriptor.PreferredResourceHeapSize, heapAlignment,
                        std::move(resourceHeapAllocator));
                }
                case ALLOCATOR_ALGORITHM_SEGMENTED_POOL: {
                    return std::make_unique<SegmentedMemoryAllocator>(
                        std::move(resourceHeapAllocator), heapAlignment);
                }
                default: {
                    UNREACHABLE();
                    return {};
                }
            }
        }

        return resourceHeapAllocator;
    }

    std::unique_ptr<MemoryAllocator> ResourceAllocator::CreateSmallBufferAllocator(
        const ALLOCATOR_DESC& descriptor,
        D3D12_HEAP_FLAGS heapFlags,
        D3D12_HEAP_TYPE heapType,
        uint64_t heapAlignment) {
        // Buffers are always 64KB aligned.
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_resource_desc
        std::unique_ptr<MemoryAllocator> smallBufferOnlyAllocator =
            std::make_unique<BufferAllocator>(this, heapType, heapFlags, D3D12_RESOURCE_FLAG_NONE,
                                              GetInitialResourceState(heapType),
                                              /*bufferSize*/ heapAlignment,
                                              /*bufferAlignment*/ heapAlignment);

        std::unique_ptr<MemoryAllocator> pooledOrNonPooledAllocator;
        if (!(descriptor.Flags & ALLOCATOR_FLAG_ALWAYS_ON_DEMAND)) {
            // Small buffers always use a 64KB heap.
            pooledOrNonPooledAllocator = std::make_unique<PooledMemoryAllocator>(
                heapAlignment, heapAlignment, std::move(smallBufferOnlyAllocator));
        } else {
            pooledOrNonPooledAllocator = std::move(smallBufferOnlyAllocator);
        }

        switch (descriptor.SubAllocationAlgorithm) {
            case ALLOCATOR_ALGORITHM_BUDDY_SYSTEM: {
                return std::make_unique<BuddyMemoryAllocator>(
                    /*systemSize*/ heapAlignment,
                    /*memorySize*/ heapAlignment,
                    /*memoryAlignment*/ heapAlignment,
                    /*memoryAllocator*/ std::move(pooledOrNonPooledAllocator));
            }
            case ALLOCATOR_ALGORITHM_SLAB: {
                // Any amount of fragmentation must be allowed for small buffers since the resource
                // heap size cannot change.
                return std::make_unique<SlabCacheAllocator>(
                    /*maxSlabSize*/ heapAlignment,
                    /*slabSize*/ heapAlignment,
                    /*slabAlignment*/ heapAlignment,
                    /*slabFragmentationLimit*/ 1,
                    /*allowSlabPrefetch*/ false,
                    /*slabMemoryGrowth*/ 1,
                    /*memoryAllocator*/ std::move(pooledOrNonPooledAllocator));
            }
            default:
                UNREACHABLE();
                return {};
        }
    }

    ResourceAllocator::~ResourceAllocator() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);

        // Destroy allocators in the reverse order they were created so we can record delete events
        // before event tracer shutdown.
        mSmallBufferAllocatorOfType = {};

        mMSAAResourceHeapAllocatorOfType = {};
        mMSAAResourceAllocatorOfType = {};

        mResourceAllocatorOfType = {};
        mResourceHeapAllocatorOfType = {};

#if defined(GPGMM_ENABLE_ALLOCATOR_LEAK_CHECKS)
        mDebugAllocator->ReportLiveAllocations();
#endif

#if defined(GPGMM_ENABLE_DEVICE_LEAK_CHECKS)
        ReportLiveDeviceObjects(mDevice);
#endif
        mResidencyManager = nullptr;

        if (mFlushEventBuffersOnDestruct) {
            FlushEventTraceToDisk();
        }
    }

    const char* ResourceAllocator::GetTypename() const {
        return "ResourceAllocator";
    }

    uint64_t ResourceAllocator::ReleaseMemory(uint64_t bytesToRelease) {
        std::lock_guard<std::mutex> lock(mMutex);
        uint64_t bytesReleased = 0;
        for (uint32_t resourceHeapTypeIndex = 0; resourceHeapTypeIndex < kNumOfResourceHeapTypes;
             resourceHeapTypeIndex++) {
            // Trim in order of largest-to-smallest heap alignment. This is because trimming larger
            // heaps will more likely exceed the amount of bytes needed then smaller ones. But if
            // this causes over-trimming, then smaller heaps would be better.
            // TODO: Consider adding controls to change policy.
            bytesReleased +=
                mSmallBufferAllocatorOfType[resourceHeapTypeIndex]->ReleaseMemory(bytesToRelease);
            if (bytesReleased >= bytesToRelease) {
                break;
            }

            bytesReleased +=
                mResourceHeapAllocatorOfType[resourceHeapTypeIndex]->ReleaseMemory(bytesToRelease);
            if (bytesReleased >= bytesToRelease) {
                break;
            }

            bytesReleased +=
                mResourceAllocatorOfType[resourceHeapTypeIndex]->ReleaseMemory(bytesToRelease);
            if (bytesReleased >= bytesToRelease) {
                break;
            }

            bytesReleased += mMSAAResourceHeapAllocatorOfType[resourceHeapTypeIndex]->ReleaseMemory(
                bytesToRelease);
            if (bytesReleased >= bytesToRelease) {
                break;
            }

            bytesReleased +=
                mMSAAResourceAllocatorOfType[resourceHeapTypeIndex]->ReleaseMemory(bytesToRelease);
            if (bytesReleased >= bytesToRelease) {
                break;
            }
        }

        // Update allocation metrics.
        if (bytesReleased > 0) {
            GetInfoInternal();
        }

        return bytesReleased;
    }

    HRESULT ResourceAllocator::CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                                              const D3D12_RESOURCE_DESC& resourceDescriptor,
                                              D3D12_RESOURCE_STATES initialResourceState,
                                              const D3D12_CLEAR_VALUE* pClearValue,
                                              ResourceAllocation** ppResourceAllocationOut) {
        GPGMM_TRACE_EVENT_OBJECT_CALL(
            "ResourceAllocator.CreateResource",
            (CREATE_RESOURCE_DESC{allocationDescriptor, resourceDescriptor, initialResourceState,
                                  pClearValue}));

        std::lock_guard<std::mutex> lock(mMutex);
        ComPtr<ResourceAllocation> allocation;
        ReturnIfFailed(CreateResourceInternal(allocationDescriptor, resourceDescriptor,
                                              initialResourceState, pClearValue, &allocation));

        // Insert a new (debug) allocator layer into the allocation so it can report details used
        // during leak checks. Since we don't want to use it unless we are debugging, we hide it
        // behind a macro.
#if defined(GPGMM_ENABLE_ALLOCATOR_LEAK_CHECKS)
        mDebugAllocator->AddLiveAllocation(allocation.Get());
#endif

        // Update the current usage counters.
        if (mUseDetailedTimingEvents) {
            GetInfoInternal();
        }

#if defined(GPGMM_ENABLE_RESOURCE_MEMORY_ALIGN_CHECKS)
        if (allocation->GetSize() > allocation->GetRequestSize()) {
            DebugEvent(GetTypename(), EventMessageId::AlignmentMismatch)
                << "Resource allocation is larger then the requested size (" +
                       std::to_string(allocation->GetSize()) + " vs " +
                       std::to_string(allocation->GetRequestSize()) + " bytes).";
        }
#endif

        if (ppResourceAllocationOut != nullptr) {
            *ppResourceAllocationOut = allocation.Detach();
        }

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResourceInternal(
        const ALLOCATION_DESC& allocationDescriptor,
        const D3D12_RESOURCE_DESC& resourceDescriptor,
        D3D12_RESOURCE_STATES initialResourceState,
        const D3D12_CLEAR_VALUE* clearValue,
        ResourceAllocation** ppResourceAllocationOut) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResourceAllocator.CreateResource");

        // If d3d tells us the resource size is invalid, treat the error as OOM.
        // Otherwise, creating a very large resource could overflow the allocator.
        D3D12_RESOURCE_DESC newResourceDesc = resourceDescriptor;
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), newResourceDesc);
        if (resourceInfo.SizeInBytes > mCaps->GetMaxResourceSize()) {
            return E_OUTOFMEMORY;
        }

        const RESOURCE_HEAP_TYPE resourceHeapType =
            GetResourceHeapType(newResourceDesc.Dimension, allocationDescriptor.HeapType,
                                newResourceDesc.Flags, mResourceHeapTier);
        if (resourceHeapType == RESOURCE_HEAP_TYPE_INVALID) {
            return E_INVALIDARG;
        }

        // Check memory requirements.
        bool isAlwaysCommitted = mIsAlwaysCommitted;
        D3D12_HEAP_FLAGS heapFlags = GetHeapFlags(resourceHeapType, IsCreateHeapNotResident());
        if (!Flags(heapFlags).HasFlags(allocationDescriptor.ExtraRequiredHeapFlags)) {
            DebugEvent(GetTypename())
                << "Required heap flags are incompatible with resource heap type ("
                << std::to_string(allocationDescriptor.ExtraRequiredHeapFlags) << " vs "
                << std::to_string(heapFlags) + ").";

            heapFlags |= allocationDescriptor.ExtraRequiredHeapFlags;

            // Fall-back to committed if resource heap is incompatible.
            // TODO: Considering adding resource heap types.
            isAlwaysCommitted = true;
        }

        bool neverSubAllocate =
            allocationDescriptor.Flags & ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;

        const bool isMSAA = resourceDescriptor.SampleDesc.Count > 1;

        const bool requiresPadding = allocationDescriptor.RequireResourceHeapPadding > 0;

        // Attempt to allocate using the most effective allocator.;
        MemoryAllocator* allocator = nullptr;

        // The requested size should always be the non-allocated size when possible. The
        // sub-allocator uses the unaligned size to determine the size of the heap required to stay
        // within the fragmentation threshold.
        //
        // Only the buffer size can be computed directly from the resource descriptor (width always
        // represents 1D coorinates, in bytes).
        MemoryAllocationRequest request = {};
        request.SizeInBytes = (newResourceDesc.Dimension == D3D12_RESOURCE_DIMENSION_BUFFER)
                                  ? newResourceDesc.Width
                                  : resourceInfo.SizeInBytes;
        request.NeverAllocate =
            (allocationDescriptor.Flags & ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY);
        request.AlwaysPrefetch =
            (allocationDescriptor.Flags & ALLOCATION_FLAG_ALWAYS_PREFETCH_MEMORY);
        request.AlwaysCacheSize = (allocationDescriptor.Flags & ALLOCATION_FLAG_ALWAYS_CACHE_SIZE);
        request.AvailableForAllocation = mCaps->GetMaxResourceHeapSize();

        // Apply extra padding to the resource heap size, if specified.
        // Padding can only be applied to standalone non-committed resources.
        if (GPGMM_UNLIKELY(requiresPadding)) {
            request.SizeInBytes += allocationDescriptor.RequireResourceHeapPadding;
            if (!neverSubAllocate) {
                DebugLog() << "Sub-allocation disabled when padding is requested.";
                neverSubAllocate = true;
            }
        }

        // Limit available memory to unused budget when residency is enabled.
        if (mResidencyManager != nullptr) {
            const DXGI_MEMORY_SEGMENT_GROUP segment =
                mResidencyManager->GetMemorySegmentGroup(allocationDescriptor.HeapType);
            DXGI_QUERY_VIDEO_MEMORY_INFO* currentVideoInfo =
                mResidencyManager->GetVideoMemoryInfo(segment);

            // If over-budget, only free memory is left available.
            // TODO: Consider optimizing GetInfoInternal().
            if (currentVideoInfo->CurrentUsage > currentVideoInfo->Budget) {
                request.AvailableForAllocation = GetInfoInternal().FreeMemoryUsage;

                DebugEvent(GetTypename())
                    << "Current usage exceeded budget ("
                    << std::to_string(currentVideoInfo->CurrentUsage) << " vs "
                    << std::to_string(currentVideoInfo->Budget) + " bytes).";

            } else {
                request.AvailableForAllocation =
                    currentVideoInfo->Budget - currentVideoInfo->CurrentUsage;
            }
        }

        // Attempt to create a resource allocation within the same resource.
        // This has the same performace as sub-allocating resource heaps without the
        // drawback of requiring resource heaps to be 64KB size-aligned. However, this
        // strategy only works in a few cases (ex. small constant buffers uploads) so it should be
        // tried before sub-allocating resource heaps.
        // The time and space complexity of is defined by the sub-allocation algorithm used.
        if (allocationDescriptor.Flags & ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE &&
            resourceInfo.Alignment > newResourceDesc.Width &&
            newResourceDesc.Dimension == D3D12_RESOURCE_DIMENSION_BUFFER &&
            GetInitialResourceState(allocationDescriptor.HeapType) == initialResourceState &&
            !isAlwaysCommitted && !neverSubAllocate) {
            allocator = mSmallBufferAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();

            // GetResourceAllocationInfo() always rejects smaller alignments than 64KB.
            if (resourceDescriptor.Alignment == 0) {
                // Only constant buffers must be 256B aligned.
                request.Alignment = (initialResourceState == D3D12_RESOURCE_STATE_GENERIC_READ)
                                        ? D3D12_CONSTANT_BUFFER_DATA_PLACEMENT_ALIGNMENT
                                        : NextPowerOfTwo(newResourceDesc.Width);
            } else {
                request.Alignment = resourceDescriptor.Alignment;
            }

            // Pre-fetching is not supported for resources since the pre-fetch thread must allocate
            // through |this| via CreateCommittedResource which is already locked by
            // CreateResource().
            request.AlwaysPrefetch = false;

            ReturnIfSucceeded(TryAllocateResource(
                mDevice.Get(), allocator, request, [&](const auto& subAllocation) -> HRESULT {
                    // Committed resource implicitly creates a resource heap which can be
                    // used for sub-allocation.
                    ComPtr<ID3D12Resource> committedResource;
                    Heap* resourceHeap = ToBackend(subAllocation.GetMemory());
                    ReturnIfFailed(resourceHeap->QueryInterface(IID_PPV_ARGS(&committedResource)));

                    RESOURCE_ALLOCATION_DESC allocationDesc = {};
                    allocationDesc.RequestSizeInBytes = resourceDescriptor.Width;
                    allocationDesc.HeapOffset = kInvalidOffset;
                    allocationDesc.Method = AllocationMethod::kSubAllocatedWithin;
                    allocationDesc.OffsetFromResource = subAllocation.GetOffset();
                    allocationDesc.DebugName = allocationDescriptor.DebugName;

                    ReturnIfFailed(ResourceAllocation::CreateResourceAllocation(
                        allocationDesc, mResidencyManager.Get(), subAllocation.GetAllocator(),
                        resourceHeap, subAllocation.GetBlock(), std::move(committedResource),
                        ppResourceAllocationOut));

                    return S_OK;
                }));
        }

        // Attempt to create a resource allocation by placing a resource in a sub-allocated
        // resource heap.
        // The time and space complexity of is determined by the sub-allocation algorithm used.
        if (!isAlwaysCommitted && !neverSubAllocate) {
            if (isMSAA) {
                allocator =
                    mMSAAResourceAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();
            } else {
                allocator = mResourceAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();
            }

            request.Alignment = resourceInfo.Alignment;

            ReturnIfSucceeded(TryAllocateResource(
                mDevice.Get(), allocator, request, [&](const auto& subAllocation) -> HRESULT {
                    // Resource is placed at an offset corresponding to the allocation offset.
                    // Each allocation maps to a disjoint (physical) address range so no physical
                    // memory is can be aliased or will overlap.
                    ComPtr<ID3D12Resource> placedResource;
                    Heap* resourceHeap = ToBackend(subAllocation.GetMemory());
                    ReturnIfFailed(CreatePlacedResource(resourceHeap, subAllocation.GetOffset(),
                                                        &newResourceDesc, clearValue,
                                                        initialResourceState, &placedResource));

                    RESOURCE_ALLOCATION_DESC allocationDesc = {};
                    allocationDesc.RequestSizeInBytes = request.SizeInBytes;
                    allocationDesc.HeapOffset = subAllocation.GetOffset();
                    allocationDesc.Method = subAllocation.GetMethod();
                    allocationDesc.OffsetFromResource = 0;
                    allocationDesc.DebugName = allocationDescriptor.DebugName;

                    ReturnIfFailed(ResourceAllocation::CreateResourceAllocation(
                        allocationDesc, mResidencyManager.Get(), subAllocation.GetAllocator(),
                        resourceHeap, subAllocation.GetBlock(), std::move(placedResource),
                        ppResourceAllocationOut));

                    return S_OK;
                }));
        }

        // Attempt to create a resource allocation by placing a single resource fully contained
        // in a resource heap. This strategy is slightly better then creating a committed
        // resource because a placed resource's heap will not be reallocated by the OS until
        // ReleaseMemory() is called. The time and space complexity is determined by the allocator
        // type.
        if (!isAlwaysCommitted) {
            if (isMSAA) {
                allocator =
                    mMSAAResourceHeapAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();
            } else {
                allocator =
                    mResourceHeapAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();
            }

            request.Alignment = allocator->GetMemoryAlignment();

            ReturnIfSucceeded(TryAllocateResource(
                mDevice.Get(), allocator, request, [&](const auto& allocation) -> HRESULT {
                    Heap* resourceHeap = ToBackend(allocation.GetMemory());
                    ComPtr<ID3D12Resource> placedResource;
                    ReturnIfFailed(CreatePlacedResource(resourceHeap, allocation.GetOffset(),
                                                        &newResourceDesc, clearValue,
                                                        initialResourceState, &placedResource));

                    RESOURCE_ALLOCATION_DESC allocationDesc = {};
                    allocationDesc.RequestSizeInBytes = request.SizeInBytes;
                    allocationDesc.HeapOffset = allocation.GetOffset();
                    allocationDesc.Method = allocation.GetMethod();
                    allocationDesc.OffsetFromResource = 0;
                    allocationDesc.DebugName = allocationDescriptor.DebugName;

                    ReturnIfFailed(ResourceAllocation::CreateResourceAllocation(
                        allocationDesc, mResidencyManager.Get(), allocation.GetAllocator(),
                        resourceHeap, allocation.GetBlock(), std::move(placedResource),
                        ppResourceAllocationOut));

                    return S_OK;
                }));
        }

        // Attempt to create a standalone committed resource. This strategy is the safest but also
        // the most expensive so it's used as a last resort or if the developer needs larger
        // allocations where sub-allocation or pooling is otherwise ineffective.
        // The time and space complexity of committed resource is driver-defined.
        if (request.NeverAllocate) {
            return E_OUTOFMEMORY;
        }

        // Committed resources cannot specify resource heap size.
        if (GPGMM_UNLIKELY(requiresPadding)) {
            ErrorLog() << "A padding was specified but no resource allocator could be used.";
            return E_FAIL;
        }

        if (!isAlwaysCommitted) {
            InfoEvent(GetTypename(), EventMessageId::AllocatorFailed)
                << "Unable to allocate by using a heap, falling back to a committed resource.";
        }

        ComPtr<ID3D12Resource> committedResource;
        Heap* resourceHeap = nullptr;
        ReturnIfFailed(CreateCommittedResource(
            allocationDescriptor.HeapType, heapFlags, resourceInfo, &newResourceDesc, clearValue,
            initialResourceState, &committedResource, &resourceHeap));

        // Using committed resources will create a tightly allocated resource allocations.
        // This means the block and heap size should be equal (modulo driver padding).
        const uint64_t allocationSize = resourceHeap->GetSize();
        mInfo.UsedMemoryUsage += allocationSize;
        mInfo.UsedMemoryCount++;
        mInfo.UsedBlockUsage += allocationSize;

        RESOURCE_ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapOffset = kInvalidOffset;
        allocationDesc.RequestSizeInBytes = request.SizeInBytes;
        allocationDesc.Method = AllocationMethod::kStandalone;
        allocationDesc.OffsetFromResource = 0;
        allocationDesc.DebugName = allocationDescriptor.DebugName;

        ReturnIfFailed(ResourceAllocation::CreateResourceAllocation(
            allocationDesc, mResidencyManager.Get(), this, resourceHeap, nullptr,
            std::move(committedResource), ppResourceAllocationOut));

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResource(ComPtr<ID3D12Resource> resource,
                                              ResourceAllocation** ppResourceAllocationOut) {
        std::lock_guard<std::mutex> lock(mMutex);

        if (!ppResourceAllocationOut) {
            return E_POINTER;
        }

        if (resource == nullptr) {
            return E_INVALIDARG;
        }

        D3D12_RESOURCE_DESC desc = resource->GetDesc();
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), desc);

        D3D12_HEAP_PROPERTIES heapProperties;
        ReturnIfFailed(resource->GetHeapProperties(&heapProperties, nullptr));

        HEAP_DESC resourceHeapDesc = {};
        resourceHeapDesc.SizeInBytes = resourceInfo.SizeInBytes;
        resourceHeapDesc.Alignment = resourceInfo.Alignment;
        resourceHeapDesc.IsExternal = true;
        resourceHeapDesc.HeapType = heapProperties.Type;

        Heap* resourceHeap = nullptr;
        ReturnIfFailed(Heap::CreateHeap(
            resourceHeapDesc, /*residencyManager*/ nullptr,
            [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
                ComPtr<ID3D12Pageable> pageable;
                resource.As(&pageable);

                *ppPageableOut = pageable.Detach();

                return S_OK;
            },
            &resourceHeap));

        mInfo.UsedMemoryUsage += resourceInfo.SizeInBytes;
        mInfo.UsedMemoryCount++;
        mInfo.UsedBlockUsage += resourceInfo.SizeInBytes;

        RESOURCE_ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapOffset = kInvalidSize;
        allocationDesc.RequestSizeInBytes = resourceInfo.SizeInBytes;
        allocationDesc.Method = AllocationMethod::kStandalone;
        allocationDesc.OffsetFromResource = 0;

        ReturnIfFailed(ResourceAllocation::CreateResourceAllocation(
            allocationDesc, nullptr, this, resourceHeap, nullptr, std::move(resource),
            ppResourceAllocationOut));

        return S_OK;
    }

    HRESULT ResourceAllocator::CreatePlacedResource(Heap* const resourceHeap,
                                                    uint64_t resourceOffset,
                                                    const D3D12_RESOURCE_DESC* resourceDescriptor,
                                                    const D3D12_CLEAR_VALUE* clearValue,
                                                    D3D12_RESOURCE_STATES initialResourceState,
                                                    ID3D12Resource** placedResourceOut) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResourceAllocator.CreatePlacedResource");

        // Before calling CreatePlacedResource, we must ensure the target heap is resident or
        // CreatePlacedResource will fail.
        ComPtr<ID3D12Resource> placedResource;
        {
            ComPtr<ID3D12Heap> heap;
            ReturnIfFailed(resourceHeap->QueryInterface(IID_PPV_ARGS(&heap)));

            ScopedResidencyLock residencyLock(mResidencyManager.Get(), resourceHeap);
            ReturnIfFailed(mDevice->CreatePlacedResource(
                heap.Get(), resourceOffset, resourceDescriptor, initialResourceState, clearValue,
                IID_PPV_ARGS(&placedResource)));
        }

        *placedResourceOut = placedResource.Detach();

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateCommittedResource(
        D3D12_HEAP_TYPE heapType,
        D3D12_HEAP_FLAGS heapFlags,
        const D3D12_RESOURCE_ALLOCATION_INFO& info,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* clearValue,
        D3D12_RESOURCE_STATES initialResourceState,
        ID3D12Resource** commitedResourceOut,
        Heap** resourceHeapOut) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResourceAllocator.CreateCommittedResource");

        HEAP_DESC resourceHeapDesc = {};
        resourceHeapDesc.SizeInBytes = info.SizeInBytes;
        resourceHeapDesc.DebugName = "Resource heap (committed)";
        resourceHeapDesc.Alignment = info.Alignment;
        resourceHeapDesc.AlwaysInBudget = mIsAlwaysInBudget;
        resourceHeapDesc.HeapType = heapType;

        // Since residency is per heap, every committed resource is wrapped in a heap object.
        Heap* resourceHeap = nullptr;
        ComPtr<ID3D12Resource> committedResource;

        ReturnIfFailed(Heap::CreateHeap(
            resourceHeapDesc, mResidencyManager.Get(),
            [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
                // Resource heap flags must be inferred by the resource descriptor and cannot be
                // explicitly provided to CreateCommittedResource.
                heapFlags &= ~(D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES |
                               D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES | D3D12_HEAP_FLAG_DENY_BUFFERS);

                D3D12_HEAP_PROPERTIES heapProperties = {};
                heapProperties.Type = heapType;

                ReturnIfFailed(mDevice->CreateCommittedResource(
                    &heapProperties, heapFlags, resourceDescriptor, initialResourceState,
                    clearValue, IID_PPV_ARGS(&committedResource)));

                ComPtr<ID3D12Pageable> pageable;
                ReturnIfFailed(committedResource.As(&pageable));
                *ppPageableOut = pageable.Detach();
                return S_OK;
            },
            &resourceHeap));

        if (commitedResourceOut != nullptr) {
            *commitedResourceOut = committedResource.Detach();
        }

        *resourceHeapOut = resourceHeap;

        return S_OK;
    }

    RESOURCE_ALLOCATOR_INFO ResourceAllocator::GetInfo() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return GetInfoInternal();
    }

    RESOURCE_ALLOCATOR_INFO ResourceAllocator::GetInfoInternal() const {
        TRACE_EVENT0(TraceEventCategory::Default, "ResourceAllocator.GetInfo");

        // ResourceAllocator itself could call CreateCommittedResource directly.
        RESOURCE_ALLOCATOR_INFO result = mInfo;

        for (uint32_t resourceHeapTypeIndex = 0; resourceHeapTypeIndex < kNumOfResourceHeapTypes;
             resourceHeapTypeIndex++) {
            result += mSmallBufferAllocatorOfType[resourceHeapTypeIndex]->GetInfo();

            result += mMSAAResourceHeapAllocatorOfType[resourceHeapTypeIndex]->GetInfo();
            result += mMSAAResourceAllocatorOfType[resourceHeapTypeIndex]->GetInfo();

            result += mResourceAllocatorOfType[resourceHeapTypeIndex]->GetInfo();
            result += mResourceHeapAllocatorOfType[resourceHeapTypeIndex]->GetInfo();
        }

        GPGMM_TRACE_EVENT_METRIC(
            "GPU allocation utilization (%)",
            SafeDivide(result.UsedBlockUsage, result.UsedMemoryUsage + result.FreeMemoryUsage) *
                100);

        GPGMM_TRACE_EVENT_METRIC("GPU allocation free (MB)",
                                 GPGMM_BYTES_TO_MB(result.FreeMemoryUsage));

        GPGMM_TRACE_EVENT_METRIC(
            "GPU allocation prefetch coverage (%)",
            SafeDivide(result.PrefetchedMemoryMissesEliminated,
                       result.PrefetchedMemoryMisses + result.PrefetchedMemoryMissesEliminated) *
                100);

        GPGMM_TRACE_EVENT_METRIC(
            "GPU allocation size cache hits (%)",
            SafeDivide(result.SizeCacheHits, result.SizeCacheMisses + result.SizeCacheHits) * 100);

        return result;
    }

    // static
    HRESULT ResourceAllocator::ReportLiveDeviceObjects(ComPtr<ID3D12Device> device) {
        // Debug layer was never enabled.
        ComPtr<ID3D12DebugDevice> debugDevice;
        if (FAILED(device.As(&debugDevice))) {
            return S_OK;
        }

        const D3D12_RLDO_FLAGS rldoFlags = D3D12_RLDO_DETAIL | D3D12_RLDO_IGNORE_INTERNAL;
        ReturnIfFailed(debugDevice->ReportLiveDeviceObjects(rldoFlags));

        ComPtr<ID3D12InfoQueue> leakMessageQueue;
        ReturnIfFailed(device.As(&leakMessageQueue));

        // Report live device objects that could be created by GPGMM by checking the global filter.
        // This is because the allowList filter cannot easily be made exclusive to these IDs.
        for (uint64_t i = 0; i < leakMessageQueue->GetNumStoredMessagesAllowedByRetrievalFilter();
             ++i) {
            SIZE_T messageLength = 0;
            ReturnIfFailed(leakMessageQueue->GetMessage(i, nullptr, &messageLength));

            std::unique_ptr<uint8_t[]> messageData(new uint8_t[messageLength]);
            D3D12_MESSAGE* message = reinterpret_cast<D3D12_MESSAGE*>(messageData.get());
            ReturnIfFailed(leakMessageQueue->GetMessage(i, message, &messageLength));

            switch (message->ID) {
                case D3D12_MESSAGE_ID_LIVE_HEAP:
                case D3D12_MESSAGE_ID_LIVE_RESOURCE: {
                    gpgmm::WarnEvent("Device")
                        << "Leak detected: " + std::string(message->pDescription);
                } break;
                default:
                    break;
            }
        }

        leakMessageQueue->PopRetrievalFilter();
        return S_OK;
    }

    void ResourceAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        TRACE_EVENT0(TraceEventCategory::Default, "ResourceAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        const uint64_t allocationSize = allocation->GetSize();
        mInfo.UsedMemoryUsage -= allocationSize;
        mInfo.UsedMemoryCount--;
        mInfo.UsedBlockUsage -= allocationSize;

        SafeRelease(allocation);
    }

    bool ResourceAllocator::IsCreateHeapNotResident() const {
        return mResidencyManager != nullptr && !mIsAlwaysInBudget;
    }

    HRESULT ResourceAllocator::CheckFeatureSupport(ALLOCATOR_FEATURE feature,
                                                   void* pFeatureSupportData,
                                                   uint32_t featureSupportDataSize) {
        switch (feature) {
            case RESOURCE_ALLOCATOR_FEATURE_SUBALLOCATION_SUPPORT: {
                ALLOCATOR_FEATURE_DATA_SUBALLOCATION_SUPPORT data = {};
                if (featureSupportDataSize != sizeof(data)) {
                    return E_INVALIDARG;
                }
                data.IsResourceAccessAlwaysCoherent = mCaps->IsResourceAccessAlwaysCoherent();
                memcpy(pFeatureSupportData, &data, featureSupportDataSize);
                return S_OK;
            }
            default: {
                WarningLog() << "CheckFeatureSupport does not support feature (" +
                                    std::to_string(feature) + ").";
                return E_INVALIDARG;
            }
        }

        return E_INVALIDARG;
    }

}  // namespace gpgmm::d3d12
