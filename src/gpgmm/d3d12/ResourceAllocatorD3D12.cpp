// Copyright 2019 The Dawn Authors
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

#include "gpgmm/d3d12/ResourceAllocatorD3D12.h"

#include "gpgmm/common/BuddyMemoryAllocator.h"
#include "gpgmm/common/DedicatedMemoryAllocator.h"
#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/PooledMemoryAllocator.h"
#include "gpgmm/common/SegmentedMemoryAllocator.h"
#include "gpgmm/common/SentinelMemoryAllocator.h"
#include "gpgmm/common/SlabMemoryAllocator.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/BufferAllocatorD3D12.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/EventMessageD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/LogD3D12.h"
#include "gpgmm/d3d12/ResidencyHeapD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationTrackingAllocatorD3D12.h"
#include "gpgmm/d3d12/ResourceHeapAllocatorD3D12.h"
#include "gpgmm/d3d12/ResourceSizeD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace gpgmm::d3d12 {

    static constexpr uint64_t kMinBlockToMemoryCountReportingThreshold = 8u;
    static constexpr double kMinAllocationUsageReportingThreshold = 0.5;

    namespace {

        // Combines heap type and flags used to allocate memory for resources into a single type for
        // allocator lookup.
        enum RESOURCE_HEAP_TYPE {
            // Resource heap tier 2
            // Resource heaps contain all buffer and textures types.
            RESOURCE_HEAP_TYPE_READBACK_ALLOW_ALL_BUFFERS_AND_TEXTURES = 0,
            RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ALL_BUFFERS_AND_TEXTURES = 1,
            RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ALL_BUFFERS_AND_TEXTURES = 2,

            // Resource heap tier 1
            // Resource heaps contain buffers or textures but not both.
            RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_BUFFERS = 3,
            RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_BUFFERS = 4,
            RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_BUFFERS = 5,

            // Further heap attribution is required for tier 1: textures are categorized into render
            // target or depth-stencil textures but not both.
            RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES = 6,
            RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_RT_OR_DS_TEXTURES = 7,
            RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES = 8,
            RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_RT_OR_DS_TEXTURES = 9,
            RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES = 10,
            RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES = 11,

            RESOURCE_HEAP_TYPE_INVALID,
        };

        // Checks what D3D12_HEAP_FLAGS allow texture resource types (eg. 1D, 2D, 3D).
        // https://learn.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_flags
        bool IsTexturesAllowed(D3D12_HEAP_FLAGS heapFlags,
                               bool isMSAA,
                               D3D12_RESOURCE_HEAP_TIER resourceHeapTier) {
            // Mixed heaps require D3D12_RESOURCE_HEAP_TIER_2.
            if (HasAllFlags(heapFlags, D3D12_HEAP_FLAG_ALLOW_ALL_BUFFERS_AND_TEXTURES) &&
                resourceHeapTier >= D3D12_RESOURCE_HEAP_TIER_2) {
                return true;
            }

            // Non-RT and non-DS textures.
            if (HasAllFlags(heapFlags, D3D12_HEAP_FLAG_ALLOW_ONLY_NON_RT_DS_TEXTURES)) {
                return true;
            }

            // RT or DS only textures.
            if (HasAllFlags(heapFlags, D3D12_HEAP_FLAG_ALLOW_ONLY_RT_DS_TEXTURES)) {
                return true;
            }

            // MSAA textures cannot be used with display heaps.
            if (HasAllFlags(heapFlags, D3D12_HEAP_FLAG_ALLOW_DISPLAY)) {
                return !isMSAA;
            }

            return false;
        }

        // Checks what D3D12_HEAP_FLAGS allow buffer resource types.
        // https://learn.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_flags
        bool IsBuffersAllowed(D3D12_HEAP_FLAGS heapFlags,
                              D3D12_RESOURCE_HEAP_TIER resourceHeapTier) {
            // Mixed heaps require D3D12_RESOURCE_HEAP_TIER_2.
            if (HasAllFlags(heapFlags, D3D12_HEAP_FLAG_ALLOW_ALL_BUFFERS_AND_TEXTURES) &&
                resourceHeapTier >= D3D12_RESOURCE_HEAP_TIER_2) {
                return true;
            }

            // Buffers only.
            if (HasAllFlags(heapFlags, D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS)) {
                return true;
            }

            return false;
        }

        D3D12_HEAP_TYPE GetHeapType(RESOURCE_HEAP_TYPE resourceHeapType) {
            switch (resourceHeapType) {
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_RT_OR_DS_TEXTURES:
                    return D3D12_HEAP_TYPE_READBACK;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES:
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES:
                    return D3D12_HEAP_TYPE_DEFAULT;
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_BUFFERS:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ALL_BUFFERS_AND_TEXTURES:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_RT_OR_DS_TEXTURES:
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
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES:
                    return createHeapFlags | D3D12_HEAP_FLAG_ALLOW_ONLY_NON_RT_DS_TEXTURES;
                case RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES:
                case RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_RT_OR_DS_TEXTURES:
                case RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_RT_OR_DS_TEXTURES:
                    return createHeapFlags | D3D12_HEAP_FLAG_ALLOW_ONLY_RT_DS_TEXTURES;
                default:
                    UNREACHABLE();
                    return D3D12_HEAP_FLAG_NONE;
            }
        }

        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_flags
        uint64_t GetHeapAlignment(D3D12_HEAP_FLAGS heapFlags, bool allowMSAA) {
            // Buffers are always 64KB aligned.
            // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_resource_desc
            const D3D12_HEAP_FLAGS denyAllTexturesFlags =
                D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES | D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES;
            if (HasAllFlags(heapFlags, denyAllTexturesFlags)) {
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
                        case D3D12_HEAP_TYPE_UPLOAD: {
                            if ((flags & D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL) ||
                                (flags & D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET)) {
                                return RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_RT_OR_DS_TEXTURES;
                            }
                            return RESOURCE_HEAP_TYPE_UPLOAD_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES;
                        }

                        case D3D12_HEAP_TYPE_DEFAULT: {
                            if ((flags & D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL) ||
                                (flags & D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET)) {
                                return RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_RT_OR_DS_TEXTURES;
                            }
                            return RESOURCE_HEAP_TYPE_DEFAULT_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES;
                        }

                        case D3D12_HEAP_TYPE_READBACK: {
                            if ((flags & D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL) ||
                                (flags & D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET)) {
                                return RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_RT_OR_DS_TEXTURES;
                            }
                            return RESOURCE_HEAP_TYPE_READBACK_ALLOW_ONLY_NON_RT_OR_DS_TEXTURES;
                        }

                        case D3D12_HEAP_TYPE_CUSTOM:
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
                    return D3D12_RESOURCE_STATE_COMMON;
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

        D3D12_HEAP_TYPE GetHeapType(D3D12_RESOURCE_STATES initialResourceState) {
            if (GetInitialResourceState(D3D12_HEAP_TYPE_UPLOAD) == initialResourceState) {
                return D3D12_HEAP_TYPE_UPLOAD;
            }

            if (GetInitialResourceState(D3D12_HEAP_TYPE_READBACK) == initialResourceState) {
                return D3D12_HEAP_TYPE_READBACK;
            }

            return D3D12_HEAP_TYPE_DEFAULT;
        }

        // RAII wrapper to lock/unlock heap from the residency cache.
        class ScopedResidencyLock final {
          public:
            ScopedResidencyLock(ResidencyManager* const residencyManager, ResidencyHeap* const heap)
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
            ResidencyHeap* const mHeap;
        };

        D3D12_HEAP_PROPERTIES GetHeapProperties(ID3D12Device* device,
                                                D3D12_HEAP_TYPE heapType,
                                                bool isCustomHeapsEnabled) {
            ASSERT(heapType != D3D12_HEAP_TYPE_CUSTOM);

            // Produces the corresponding properties from the corresponding heap type per this table
            // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12device-getcustomheapproperties
            if (isCustomHeapsEnabled) {
                return device->GetCustomHeapProperties(0, heapType);
            }

            D3D12_HEAP_PROPERTIES heapProperties = {};
            heapProperties.Type = heapType;
            heapProperties.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
            heapProperties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;

            return heapProperties;
        }

        D3D12_MEMORY_POOL GetMemoryPool(const D3D12_HEAP_PROPERTIES& heapProperties, bool isUMA) {
            // Custom heap types are required to specify a non-unknown pool.
            // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_heap_properties
            if (heapProperties.MemoryPoolPreference != D3D12_MEMORY_POOL_UNKNOWN) {
                return heapProperties.MemoryPoolPreference;
            }

            // Otherwise, a unknown pool corresponds to the custom heap type properties and only L1
            // exists when non-UMA adapter.
            // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-id3d12device-getcustomheapproperties
            if (!isUMA && heapProperties.Type == D3D12_HEAP_TYPE_DEFAULT) {
                return D3D12_MEMORY_POOL_L1;
            } else {
                return D3D12_MEMORY_POOL_L0;  // Physical system
            }
        }

        class ImportResourceCallbackContext {
          public:
            ImportResourceCallbackContext(ID3D12Resource* resource);
            static HRESULT GetHeap(void* pContext, ID3D12Pageable** ppPageableOut);

          private:
            HRESULT GetHeap(ID3D12Pageable** ppPageableOut);

            ID3D12Resource* mResource = nullptr;
        };

        class CreateCommittedResourceCallbackContext {
          public:
            CreateCommittedResourceCallbackContext(ID3D12Device* device,
                                                   D3D12_HEAP_PROPERTIES* heapProperties,
                                                   D3D12_HEAP_FLAGS heapFlags,
                                                   const D3D12_RESOURCE_DESC* resourceDescriptor,
                                                   const D3D12_CLEAR_VALUE* clearValue,
                                                   D3D12_RESOURCE_STATES initialResourceState);

            static HRESULT CreateHeap(void* pContext, ID3D12Pageable** ppPageableOut);

          private:
            HRESULT CreateCommittedResource(ID3D12Pageable** ppPageableOut);

            const D3D12_CLEAR_VALUE* mClearValue;
            ID3D12Device* mDevice;
            D3D12_RESOURCE_STATES mInitialResourceState;
            D3D12_HEAP_FLAGS mHeapFlags;
            D3D12_HEAP_PROPERTIES* mHeapProperties;
            const D3D12_RESOURCE_DESC* mResourceDescriptor;
        };

    }  // namespace

    HRESULT CreateResourceAllocator(const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
                                    ID3D12Device* pDevice,
                                    IDXGIAdapter* pAdapter,
                                    IResourceAllocator** ppResourceAllocatorOut,
                                    IResidencyManager** ppResidencyManagerOut = nullptr) {
        return ResourceAllocator::CreateResourceAllocator(
            allocatorDescriptor, pDevice, pAdapter, ppResourceAllocatorOut, ppResidencyManagerOut);
    }

    HRESULT CreateResourceAllocator(const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
                                    ID3D12Device* pDevice,
                                    IDXGIAdapter* pAdapter,
                                    IResidencyManager* pResidencyManager,
                                    IResourceAllocator** ppResourceAllocatorOut) {
        return ResourceAllocator::CreateResourceAllocator(
            allocatorDescriptor, pDevice, pAdapter, pResidencyManager, ppResourceAllocatorOut);
    }

    // static
    HRESULT ResourceAllocator::CreateResourceAllocator(
        const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
        ID3D12Device* pDevice,
        IDXGIAdapter* pAdapter,
        IResourceAllocator** ppResourceAllocatorOut,
        IResidencyManager** ppResidencyManagerOut) {
        GPGMM_RETURN_IF_NULLPTR(pDevice);

        ComPtr<IResidencyManager> residencyManager;
        if (ppResidencyManagerOut != nullptr) {
            ComPtr<IDXGIAdapter3> adapter3;
            if (pAdapter != nullptr) {
                GPGMM_RETURN_IF_FAILED(pAdapter->QueryInterface(IID_PPV_ARGS(&adapter3)), pDevice);
            }

            RESIDENCY_MANAGER_DESC residencyDesc = {};
            residencyDesc.MinLogLevel = allocatorDescriptor.MinLogLevel;
            residencyDesc.RecordOptions = allocatorDescriptor.RecordOptions;

            if (allocatorDescriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALWAYS_IN_BUDGET) {
                residencyDesc.Flags |= RESIDENCY_MANAGER_FLAG_ALWAYS_IN_BUDGET;
            }

            GPGMM_RETURN_IF_FAILED(ResidencyManager::CreateResidencyManager(
                                       residencyDesc, pDevice, adapter3.Get(), &residencyManager),
                                   pDevice);
        }

        ComPtr<IResourceAllocator> resourceAllocator;
        GPGMM_RETURN_IF_FAILED(CreateResourceAllocator(allocatorDescriptor, pDevice, pAdapter,
                                                       residencyManager.Get(), &resourceAllocator),
                               pDevice);

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
        const RESOURCE_ALLOCATOR_DESC& allocatorDescriptor,
        ID3D12Device* pDevice,
        IDXGIAdapter* pAdapter,
        IResidencyManager* pResidencyManager,
        IResourceAllocator** ppResourceAllocatorOut) {
        GPGMM_RETURN_IF_NULLPTR(pDevice);

        std::unique_ptr<Caps> caps;
        {
            Caps* ptr = nullptr;
            GPGMM_RETURN_IF_FAILED(Caps::CreateCaps(pDevice, pAdapter, &ptr), pDevice);
            caps.reset(ptr);
        }

        // Do not override the default min. log level specified by the residency manager.
        // Only if this allocator is without residency, does the min. log level have affect.
        // Note: the log level should be set before logging new messages.
        if (pResidencyManager == nullptr) {
            SetLogLevel(GetMessageSeverity(allocatorDescriptor.MinLogLevel));
        }

        if (allocatorDescriptor.ResourceHeapTier > caps->GetMaxResourceHeapTierSupported()) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Resource heap tier exceeds the capabilities of the device "
                   "(ResourceHeapTier:"
                << allocatorDescriptor.ResourceHeapTier << " vs "
                << caps->GetMaxResourceHeapTierSupported()
                << "). Please consider using a lower resource heap tier.";
            return GetErrorResult(ErrorCode::kInvalidArgument);
        }

        if (allocatorDescriptor.ResourceHeapTier != 0 &&
            allocatorDescriptor.ResourceHeapTier < caps->GetMaxResourceHeapTierSupported()) {
            WarnLog(MessageId::kPerformanceWarning)
                << "Resource heap tier requested was lower than what the device "
                   "supports. This is allowed but not recommended because it prevents "
                   "resources of different categories from sharing the same heap.";
        }

        if (allocatorDescriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALWAYS_IN_BUDGET &&
            !pResidencyManager) {
            WarnLog(MessageId::kPerformanceWarning)
                << "RESOURCE_ALLOCATOR_FLAG_ALWAYS_IN_BUDGET has no effect when residency "
                   "management does not exist. This is probably not what the "
                   "developer intended to do. Please consider creating a residency "
                   "manager with this resource allocator before using this flag.";
        }

        RESOURCE_ALLOCATOR_DESC newDescriptor = allocatorDescriptor;
        newDescriptor.ResourceHeapGrowthFactor =
            (allocatorDescriptor.ResourceHeapGrowthFactor >= 1.0f)
                ? allocatorDescriptor.ResourceHeapGrowthFactor
                : kDefaultMemoryGrowthFactor;

        // By default, slab-allocate from a sorted segmented list.
        if (newDescriptor.PoolAlgorithm == RESOURCE_ALLOCATION_ALGORITHM_DEFAULT) {
            newDescriptor.PoolAlgorithm = RESOURCE_ALLOCATION_ALGORITHM_SEGMENTED_POOL;
        }

        if (newDescriptor.SubAllocationAlgorithm == RESOURCE_ALLOCATION_ALGORITHM_DEFAULT) {
            newDescriptor.SubAllocationAlgorithm = RESOURCE_ALLOCATION_ALGORITHM_SLAB;
        }

        // By default, UMA is allowed to use a single heap type. Unless it is explicitly disabled or
        // unsupported by the device.
        if ((allocatorDescriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALLOW_UNIFIED_MEMORY) &&
            !caps->IsAdapterCacheCoherentUMA()) {
            WarnLog(MessageId::kPerformanceWarning)
                << "RESOURCE_ALLOCATOR_FLAG_ALLOW_UNIFIED_MEMORY requested but disallowed "
                   "because the device did not support cache-coherent UMA.";
            newDescriptor.Flags ^= RESOURCE_ALLOCATOR_FLAG_ALLOW_UNIFIED_MEMORY;
        }

        if ((allocatorDescriptor.Flags & RESOURCE_ALLOCATOR_FLAG_CREATE_NOT_RESIDENT) &&
            !caps->IsCreateHeapNotResidentSupported()) {
            WarnLog(MessageId::kPerformanceWarning)
                << "RESOURCE_ALLOCATOR_FLAG_CREATE_NOT_RESIDENT was requested but disallowed "
                   "because the device did not support creation of non-resident heaps.";
            newDescriptor.Flags ^= RESOURCE_ALLOCATOR_FLAG_CREATE_NOT_RESIDENT;
        }

        // Resource heap tier is required but user didn't specify one.
        if (allocatorDescriptor.ResourceHeapTier == 0) {
            newDescriptor.ResourceHeapTier = caps->GetMaxResourceHeapTierSupported();
        }

        newDescriptor.MaxResourceHeapSize =
            (allocatorDescriptor.MaxResourceHeapSize > 0)
                ? std::min(allocatorDescriptor.MaxResourceHeapSize, caps->GetMaxResourceHeapSize())
                : caps->GetMaxResourceHeapSize();

        newDescriptor.PreferredResourceHeapSize =
            (allocatorDescriptor.PreferredResourceHeapSize == 0)
                ? kNoRequiredAlignment
                : std::min(allocatorDescriptor.PreferredResourceHeapSize,
                           caps->GetMaxResourceSize());

        newDescriptor.ResourceHeapFragmentationLimit =
            (allocatorDescriptor.ResourceHeapFragmentationLimit > 0)
                ? allocatorDescriptor.ResourceHeapFragmentationLimit
                : kDefaultMemoryFragmentationLimit;

        if (newDescriptor.PreferredResourceHeapSize > newDescriptor.MaxResourceHeapSize) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Requested preferred resource heap size exceeded the capabilities "
                   "of the device. This is probably not what the developer intended "
                   "to do. Please consider using a smaller resource heap size.";
            return GetErrorResult(ErrorCode::kInvalidArgument);
        }

        if (pResidencyManager == nullptr && newDescriptor.RecordOptions.Flags != RECORD_FLAG_NONE) {
            StartupEventTrace(allocatorDescriptor.RecordOptions.TraceFile,
                              static_cast<TraceEventPhase>(~newDescriptor.RecordOptions.Flags));

            SetEventMessageLevel(GetMessageSeverity(newDescriptor.MinRecordLevel));
        } else {
            // Do not override the event scope from a event trace already enabled.
            newDescriptor.RecordOptions.EventScope = RECORD_SCOPE_PER_PROCESS;
        }

#if defined(GPGMM_ENABLE_DEVICE_LEAK_CHECKS)
        ComPtr<ID3D12InfoQueue> leakMessageQueue;
        if (SUCCEEDED(newDescriptor.Device.As(&leakMessageQueue))) {
            D3D12_INFO_QUEUE_FILTER emptyFilter{};
            GPGMM_RETURN_IF_FAILED(leakMessageQueue->PushRetrievalFilter(&emptyFilter), mDevice);
        } else {
            WarnLog(MessageId::kInvalidArgument)
                << "GPGMM_ENABLE_DEVICE_LEAK_CHECKS has no effect because the D3D12 debug "
                   "layer was either not installed or enabled. Please call "
                   "ID3D12Debug::EnableDebugLayer before using this flag.";
        }
#endif

        std::unique_ptr<ResourceAllocator> resourceAllocator =
            std::unique_ptr<ResourceAllocator>(new ResourceAllocator(
                newDescriptor, pDevice, static_cast<ResidencyManager*>(pResidencyManager),
                std::move(caps)));

        GPGMM_TRACE_EVENT_OBJECT_SNAPSHOT(resourceAllocator.get(), newDescriptor);

        DebugLog(MessageId::kObjectCreated, resourceAllocator.get())
            << "Created resource allocator.";

        if (ppResourceAllocatorOut != nullptr) {
            *ppResourceAllocatorOut = resourceAllocator.release();
        }

        return S_OK;
    }

    ResourceAllocator::ResourceAllocator(const RESOURCE_ALLOCATOR_DESC& descriptor,
                                         ID3D12Device* pDevice,
                                         ResidencyManager* pResidencyManager,
                                         std::unique_ptr<Caps> caps)
        : mDevice(pDevice),
          mResidencyManager(pResidencyManager),
          mCaps(std::move(caps)),
          mResourceHeapTier(descriptor.ResourceHeapTier),
          mIsAlwaysCommitted(descriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALWAYS_COMMITTED),
          mIsAlwaysCreatedInBudget(descriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALWAYS_IN_BUDGET),
          mFlushEventBuffersOnDestruct(descriptor.RecordOptions.EventScope &
                                       RECORD_SCOPE_PER_INSTANCE),
          mUseDetailedTimingEvents(descriptor.RecordOptions.UseDetailedTimingEvents),
          mIsCustomHeapsEnabled(descriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALLOW_UNIFIED_MEMORY),
          mIsCreateNotResidentEnabled(descriptor.Flags &
                                      RESOURCE_ALLOCATOR_FLAG_CREATE_NOT_RESIDENT),
          mMaxResourceHeapSize(descriptor.MaxResourceHeapSize) {
        ASSERT(mDevice != nullptr);

        GPGMM_TRACE_EVENT_OBJECT_NEW(this);

        if (descriptor.Flags & RESOURCE_ALLOCATOR_FLAG_NEVER_LEAK) {
            mTrackingAllocator = std::make_unique<ResourceAllocationTrackingAllocator>();
        }

        const bool isUMA =
            (IsResidencyEnabled()) ? mResidencyManager->IsUMA() : mCaps->IsAdapterUMA();

        for (uint32_t resourceHeapTypeIndex = 0; resourceHeapTypeIndex < kNumOfResourceHeapTypes;
             resourceHeapTypeIndex++) {
            const RESOURCE_HEAP_TYPE& resourceHeapType =
                static_cast<RESOURCE_HEAP_TYPE>(resourceHeapTypeIndex);

            const D3D12_HEAP_FLAGS& heapFlags =
                GetHeapFlags(resourceHeapType, IsCreateHeapNotResidentEnabled());
            const D3D12_HEAP_TYPE heapType = GetHeapType(resourceHeapType);

            const uint64_t msaaHeapAlignment = GetHeapAlignment(heapFlags, true);
            const uint64_t heapAlignment = GetHeapAlignment(heapFlags, false);

            D3D12_HEAP_PROPERTIES heapProperties =
                GetHeapProperties(mDevice, heapType, mIsCustomHeapsEnabled);
            heapProperties.MemoryPoolPreference = GetMemoryPool(heapProperties, isUMA);

            // General-purpose allocators.
            // Used for dynamic resource allocation or when the resource size is not known at
            // compile-time.
            mResourceAllocatorOfType[resourceHeapTypeIndex] =
                CreateResourceAllocator(descriptor, heapFlags, heapProperties, heapAlignment);

            if (IsTexturesAllowed(heapFlags, /*isMSAA*/ true, mResourceHeapTier)) {
                mMSAAResourceAllocatorOfType[resourceHeapTypeIndex] = CreateResourceAllocator(
                    descriptor, heapFlags, heapProperties, msaaHeapAlignment);
            } else {
                mMSAAResourceAllocatorOfType[resourceHeapTypeIndex] =
                    std::make_unique<SentinelMemoryAllocator>();
            }

            // Dedicated allocators are used when sub-allocation cannot but heaps could still be
            // recycled.
            RESOURCE_ALLOCATOR_DESC dedicatedDescriptor = descriptor;
            dedicatedDescriptor.SubAllocationAlgorithm = RESOURCE_ALLOCATION_ALGORITHM_DEDICATED;

            mDedicatedResourceAllocatorOfType[resourceHeapTypeIndex] = CreateResourceAllocator(
                dedicatedDescriptor, heapFlags, heapProperties, heapAlignment);

            if (IsTexturesAllowed(heapFlags, /*isMSAA*/ true, mResourceHeapTier)) {
                mMSAADedicatedResourceAllocatorOfType[resourceHeapTypeIndex] =
                    CreateResourceAllocator(dedicatedDescriptor, heapFlags, heapProperties,
                                            msaaHeapAlignment);
            } else {
                mMSAADedicatedResourceAllocatorOfType[resourceHeapTypeIndex] =
                    std::make_unique<SentinelMemoryAllocator>();
            }

            if (IsBuffersAllowed(heapFlags, mResourceHeapTier)) {
                mSmallBufferAllocatorOfType[resourceHeapTypeIndex] =
                    CreateSmallBufferAllocator(descriptor, heapFlags, heapProperties, heapAlignment,
                                               GetInitialResourceState(heapType));
            } else {
                mSmallBufferAllocatorOfType[resourceHeapTypeIndex] =
                    std::make_unique<SentinelMemoryAllocator>();
            }

            // Cache resource sizes commonly requested.
            // Allows the next memory block to be made available upon request without
            // increasing memory footprint. Since resources are always sized-aligned, the
            // cached size must be requested per alignment {4KB, 64KB, or 4MB}. To avoid unbounded
            // cache growth, a known set of pre-defined sizes initializes the allocators.
#if !defined(GPGMM_DISABLE_SIZE_CACHE)
            {
                // Temporary suppress log messages emitted from internal cache-miss requests.
                ScopedLogLevel scopedLogLevel(MessageSeverity::kInfo);

                MemoryAllocationRequest cacheRequest = {};
                cacheRequest.NeverAllocate = true;
                cacheRequest.AlwaysCacheSize = true;

                for (const SizeClassInfo& sizeInfo : ResourceSize::GenerateAllClassSizes()) {
                    cacheRequest.SizeInBytes = sizeInfo.SizeInBytes;
                    cacheRequest.Alignment = sizeInfo.Alignment;

                    MemoryAllocatorBase* allocator =
                        mSmallBufferAllocatorOfType[resourceHeapTypeIndex].get();
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

    std::unique_ptr<MemoryAllocatorBase> ResourceAllocator::CreatePoolAllocator(
        RESOURCE_ALLOCATION_ALGORITHM algorithm,
        uint64_t memorySize,
        uint64_t memoryAlignment,
        bool isAlwaysOnDemand,
        std::unique_ptr<MemoryAllocatorBase> underlyingAllocator) {
        if (isAlwaysOnDemand) {
            return underlyingAllocator;
        }

        switch (algorithm) {
            case RESOURCE_ALLOCATION_ALGORITHM_FIXED_POOL: {
                return std::make_unique<PooledMemoryAllocator>(memorySize, memoryAlignment,
                                                               std::move(underlyingAllocator));
            }
            case RESOURCE_ALLOCATION_ALGORITHM_SEGMENTED_POOL: {
                return std::make_unique<SegmentedMemoryAllocator>(std::move(underlyingAllocator),
                                                                  memoryAlignment);
            }
            default: {
                UNREACHABLE();
                return {};
            }
        }
    }

    std::unique_ptr<MemoryAllocatorBase> ResourceAllocator::CreateSubAllocator(
        RESOURCE_ALLOCATION_ALGORITHM algorithm,
        uint64_t memorySize,
        uint64_t memoryAlignment,
        float memoryFragmentationLimit,
        float memoryGrowthFactor,
        bool isPrefetchAllowed,
        std::unique_ptr<MemoryAllocatorBase> underlyingAllocator) {
        switch (algorithm) {
            case RESOURCE_ALLOCATION_ALGORITHM_BUDDY_SYSTEM: {
                // System and memory size must be aligned at creation-time.
                return std::make_unique<BuddyMemoryAllocator>(
                    /*systemSize*/ LowerPowerOfTwo(mMaxResourceHeapSize),
                    /*memorySize*/ UpperPowerOfTwo(memorySize),
                    /*memoryAlignment*/ memoryAlignment,
                    /*memoryAllocator*/ std::move(underlyingAllocator));
            }
            case RESOURCE_ALLOCATION_ALGORITHM_SLAB: {
                // Min slab size is always equal to the memory size because the
                // slab allocator aligns the slab size at allocate-time.
                return std::make_unique<SlabCacheAllocator>(
                    /*maxSlabSize*/ LowerPowerOfTwo(mMaxResourceHeapSize),
                    /*minSlabSize*/ memorySize,
                    /*slabAlignment*/ memoryAlignment,
                    /*slabFragmentationLimit*/ memoryFragmentationLimit,
                    /*allowSlabPrefetch*/ isPrefetchAllowed,
                    /*slabGrowthFactor*/ memoryGrowthFactor,
                    /*memoryAllocator*/ std::move(underlyingAllocator));
            }
            case RESOURCE_ALLOCATION_ALGORITHM_DEDICATED: {
                return std::make_unique<DedicatedMemoryAllocator>(
                    /*memoryAllocator*/ std::move(underlyingAllocator), memoryAlignment);
            }
            default: {
                UNREACHABLE();
                return {};
            }
        }
    }

    std::unique_ptr<MemoryAllocatorBase> ResourceAllocator::CreateResourceAllocator(
        const RESOURCE_ALLOCATOR_DESC& descriptor,
        D3D12_HEAP_FLAGS heapFlags,
        const D3D12_HEAP_PROPERTIES& heapProperties,
        uint64_t heapAlignment) {
        std::unique_ptr<MemoryAllocatorBase> resourceHeapAllocator =
            std::make_unique<ResourceHeapAllocator>(mResidencyManager.Get(), mDevice,
                                                    heapProperties, heapFlags,
                                                    mIsAlwaysCreatedInBudget);

        const uint64_t heapSize =
            std::max(heapAlignment, AlignTo(descriptor.PreferredResourceHeapSize, heapAlignment));

        std::unique_ptr<MemoryAllocatorBase> pooledOrNonPooledAllocator =
            CreatePoolAllocator(descriptor.PoolAlgorithm, heapSize, heapAlignment,
                                (descriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALWAYS_ON_DEMAND),
                                std::move(resourceHeapAllocator));

        return CreateSubAllocator(descriptor.SubAllocationAlgorithm, heapSize, heapAlignment,
                                  descriptor.ResourceHeapFragmentationLimit,
                                  descriptor.ResourceHeapGrowthFactor,
                                  /*allowSlabPrefetch*/
                                  (descriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALLOW_PREFETCH),
                                  std::move(pooledOrNonPooledAllocator));
    }

    std::unique_ptr<MemoryAllocatorBase> ResourceAllocator::CreateSmallBufferAllocator(
        const RESOURCE_ALLOCATOR_DESC& descriptor,
        D3D12_HEAP_FLAGS heapFlags,
        const D3D12_HEAP_PROPERTIES& heapProperties,
        uint64_t heapAlignment,
        D3D12_RESOURCE_STATES initialResourceState) {
        std::unique_ptr<MemoryAllocatorBase> smallBufferOnlyAllocator =
            std::make_unique<BufferAllocator>(this, heapProperties, heapFlags,
                                              D3D12_RESOURCE_FLAG_NONE, initialResourceState);

        std::unique_ptr<MemoryAllocatorBase> pooledOrNonPooledAllocator =
            CreatePoolAllocator(descriptor.PoolAlgorithm, heapAlignment, heapAlignment,
                                (descriptor.Flags & RESOURCE_ALLOCATOR_FLAG_ALWAYS_ON_DEMAND),
                                std::move(smallBufferOnlyAllocator));

        const uint64_t heapSize =
            std::max(heapAlignment, AlignTo(descriptor.PreferredResourceHeapSize, heapAlignment));

        // Any amount of fragmentation must be allowed for small buffers since the allocation can
        // be smaller then the resource heap alignment.
        return CreateSubAllocator(
            descriptor.SubAllocationAlgorithm, heapSize, heapAlignment,
            /*memoryFragmentationLimit*/ 1.0f, descriptor.ResourceHeapGrowthFactor,
            /*allowSlabPrefetch*/ false, std::move(pooledOrNonPooledAllocator));
    }

    ResourceAllocator::~ResourceAllocator() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);

        // Give the debug allocator the first chance to report allocation leaks.
        // If allocation leak exists, report then release them immediately to prevent another leak
        // check from re-reporting the leaked allocation.
        if (mTrackingAllocator) {
            mTrackingAllocator->ReportLiveAllocations();
            mTrackingAllocator->ReleaseLiveAllocationsForTesting();
        }

        // Destroy allocators in the reverse order they were created so we can record delete events
        // before event tracer shutdown.
        mSmallBufferAllocatorOfType = {};

        mMSAADedicatedResourceAllocatorOfType = {};
        mMSAAResourceAllocatorOfType = {};

        mResourceAllocatorOfType = {};
        mDedicatedResourceAllocatorOfType = {};

#if defined(GPGMM_ENABLE_DEVICE_LEAK_CHECKS)
        ReportLiveDeviceObjects(mDevice);
#endif
        mResidencyManager = nullptr;

        if (mFlushEventBuffersOnDestruct) {
            FlushEventTraceToDisk();
        }
    }

    HRESULT ResourceAllocator::ReleaseResourceHeaps(uint64_t bytesToRelease,
                                                    uint64_t* pBytesReleased) {
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
                mDedicatedResourceAllocatorOfType[resourceHeapTypeIndex]->ReleaseMemory(
                    bytesToRelease);
            if (bytesReleased >= bytesToRelease) {
                break;
            }

            bytesReleased +=
                mResourceAllocatorOfType[resourceHeapTypeIndex]->ReleaseMemory(bytesToRelease);
            if (bytesReleased >= bytesToRelease) {
                break;
            }

            bytesReleased +=
                mMSAADedicatedResourceAllocatorOfType[resourceHeapTypeIndex]->ReleaseMemory(
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
            GetStats();
        }

        if (pBytesReleased != nullptr) {
            *pBytesReleased = bytesReleased;
        }

        if (bytesToRelease > bytesReleased) {
            return S_FALSE;
        }

        return S_OK;
    }

    D3D12_RESOURCE_ALLOCATION_INFO ResourceAllocator::GetResourceAllocationInfo(
        const D3D12_RESOURCE_DESC& resourceDescriptor) const {
        // Small textures can take advantage of smaller alignments. For example,
        // if the most detailed mip can fit under 64KB, 4KB alignments can be used.
        // Must be non-depth or without render-target to use small resource alignment.
        // This also applies to MSAA textures (4MB => 64KB).
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_resource_desc
        D3D12_RESOURCE_DESC newResourceDescriptor = resourceDescriptor;
        if (IsTexture(resourceDescriptor) && IsAllowedToUseSmallAlignment(resourceDescriptor) &&
            (resourceDescriptor.Flags & (D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET |
                                         D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL)) == 0) {
            newResourceDescriptor.Alignment = (resourceDescriptor.SampleDesc.Count > 1)
                                                  ? D3D12_SMALL_MSAA_RESOURCE_PLACEMENT_ALIGNMENT
                                                  : D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT;
        }

        // Buffers are effectively always 64KB. Specify this now to suppress D3D12 error
        // upon calling GetResourceAllocationInfo().
        if (IsBuffer(resourceDescriptor)) {
            newResourceDescriptor.Alignment = D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT;
        }

        D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            mDevice->GetResourceAllocationInfo(0, 1, &newResourceDescriptor);

        // If the requested resource alignment was rejected, let D3D tell us what the
        // required alignment is for this resource.
        if (newResourceDescriptor.Alignment != 0 &&
            newResourceDescriptor.Alignment != resourceInfo.Alignment) {
            DebugLog(MessageId::kPerformanceWarning, this)
                << "Re-aligned: " << resourceDescriptor.Alignment << " vs "
                << resourceInfo.Alignment << " bytes.";

            newResourceDescriptor.Alignment = 0;
            resourceInfo = mDevice->GetResourceAllocationInfo(0, 1, &newResourceDescriptor);
        }

        if (resourceInfo.SizeInBytes == 0) {
            resourceInfo.SizeInBytes = kInvalidSize;
        }

        return resourceInfo;
    }

    HRESULT ResourceAllocator::CreateResource(const RESOURCE_ALLOCATION_DESC& allocationDescriptor,
                                              const D3D12_RESOURCE_DESC& resourceDescriptor,
                                              D3D12_RESOURCE_STATES initialResourceState,
                                              const D3D12_CLEAR_VALUE* pClearValue,
                                              IResourceAllocation** ppResourceAllocationOut) {
        GPGMM_TRACE_EVENT_OBJECT_CALL(
            "ResourceAllocator.CreateResource",
            (RESOURCE_ALLOCATOR_CREATE_RESOURCE_PARAMS{allocationDescriptor, resourceDescriptor,
                                                       initialResourceState, pClearValue}));

        ComPtr<ResourceAllocation> allocation;
        {
            // Mutex must be destroyed before the allocation gets released. This occurs
            // when the allocation never calls Detach() below and calls release which
            // re-enters |this| upon DeallocateMemory().
            std::lock_guard<std::mutex> lock(mMutex);
            const MaybeError result =
                CreateResourceInternal(allocationDescriptor, resourceDescriptor,
                                       initialResourceState, pClearValue, &allocation);
            if (!result.IsSuccess()) {
                ErrorLog(result.GetErrorCode(), this)
                    << "Failed to create resource for allocation.";
                return GetErrorResult(result.GetErrorCode());
            }

            ASSERT(allocation->GetResource() != nullptr);

            if (GPGMM_UNLIKELY(mTrackingAllocator)) {
                GPGMM_RETURN_IF_FAILED(allocation->SetDebugName(allocationDescriptor.DebugName),
                                       mDevice);
                mTrackingAllocator->TrackAllocation(allocation.Get());
            }

            // Update the current usage counters.
            if (mUseDetailedTimingEvents) {
                GPGMM_UNUSED(GetStats());
            }

            if (allocationDescriptor.Flags &
                    RESOURCE_ALLOCATION_FLAG_ALWAYS_WARN_ON_ALIGNMENT_MISMATCH &&
                allocation->IsRequestedSizeMisaligned()) {
                WarnLog(MessageId::kPerformanceWarning, this)
                    << "Resource allocation was larger then requested: " +
                           GetBytesToSizeInUnits(allocation->GetSize()) + " vs " +
                           GetBytesToSizeInUnits(allocation->GetRequestSize()) + ".";
            }
        }

        if (ppResourceAllocationOut != nullptr) {
            *ppResourceAllocationOut = allocation.Detach();
        } else {
            return S_FALSE;
        }

        return S_OK;
    }

    // Combines AllocatorMemory and Create*Resource into a single call.
    // If the memory allocation was successful, the resource will be created using it.
    // Else, if the resource creation fails, the memory allocation will be cleaned up.
    template <typename D3D12CreateResourceFn>
    MaybeError ResourceAllocator::TryAllocateResource(MemoryAllocatorBase* allocator,
                                                      const MemoryAllocationRequest& request,
                                                      D3D12CreateResourceFn&& createResourceFn) {
        ASSERT(allocator != nullptr);

        ResultOrError<std::unique_ptr<MemoryAllocationBase>> result =
            allocator->TryAllocateMemory(request);
        if (!result.IsSuccess()) {
            // NeverAllocate always fails, so suppress it.
            if (!request.NeverAllocate) {
                WarnEvent(MessageId::kPerformanceWarning, this)
                    << "Unable to allocate memory for request.";
            }
            return result.AcquireError();
        }

        std::unique_ptr<MemoryAllocationBase> allocation = result.AcquireResult();
        ASSERT(allocation != nullptr);

        HRESULT hr = createResourceFn(*allocation);
        if (FAILED(hr)) {
            ErrorLog(ErrorCode::kAllocationFailed, this)
                << "Failed to create resource using allocation.";
            allocator->DeallocateMemory(std::move(allocation));
        }
        return GetErrorCode(hr);
    }

    MaybeError ResourceAllocator::CreateResourceInternal(
        const RESOURCE_ALLOCATION_DESC& allocationDescriptor,
        const D3D12_RESOURCE_DESC& resourceDescriptor,
        D3D12_RESOURCE_STATES initialResourceState,
        const D3D12_CLEAR_VALUE* clearValue,
        ResourceAllocation** ppResourceAllocationOut) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResourceAllocator.CreateResource");

        // If d3d tells us the resource size is invalid, treat the error as OOM.
        // Otherwise, creating a very large resource could overflow the allocator.
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(resourceDescriptor);
        if (resourceInfo.SizeInBytes > mMaxResourceHeapSize) {
            ErrorLog(ErrorCode::kSizeExceeded, this)
                << "Unable to create resource allocation because the resource size exceeded "
                   "the capabilities of the device: "
                << GetBytesToSizeInUnits(resourceInfo.SizeInBytes) << " vs "
                << GetBytesToSizeInUnits(mMaxResourceHeapSize);
            return ErrorCode::kOutOfMemory;
        }

        D3D12_RESOURCE_DESC newResourceDesc = resourceDescriptor;
        newResourceDesc.Alignment = resourceInfo.Alignment;

        // If the heap type was not specified, infer it using the initial resource state.
        D3D12_HEAP_TYPE heapType = allocationDescriptor.HeapType;
        if (heapType == 0 || heapType == D3D12_HEAP_TYPE_CUSTOM) {
            heapType = GetHeapType(initialResourceState);
        }

        // Attribution of heaps may be abandoned but the original heap type is needed to
        // check if sub-allocation within is allowed. Since default heaps do not require a
        // persistent resource state once created, they are disallowed.
        const bool isCreatedResourceStateRequired =
            (heapType != D3D12_HEAP_TYPE_DEFAULT) &&
            (GetInitialResourceState(heapType) == initialResourceState);

        // Abandon the attribution of heaps when isCacheCoherentUMA is true by always using the
        // custom equivelent of upload heap everywhere. This optimizes resource allocation by
        // allowing the same resource allocator to be used, improving heap reuse. However, CPU
        // read-back would be inefficent since upload heaps on UMA adapters are usually
        // write-combined (vs write-back) so leave read back heaps alone.
        if (!(allocationDescriptor.Flags & RESOURCE_ALLOCATION_FLAG_ALWAYS_ATTRIBUTE_HEAPS) &&
            mIsCustomHeapsEnabled) {
            if (allocationDescriptor.HeapType != D3D12_HEAP_TYPE_READBACK) {
                heapType = D3D12_HEAP_TYPE_UPLOAD;
            } else {
                WarnLog(MessageId::kPerformanceWarning, this)
                    << "Unable to optimize resource allocation for supported UMA adapter "
                       "due to D3D12_HEAP_TYPE_READBACK being specified. Please consider "
                       "using an unspecified heap type if CPU read-back efficency is "
                       "not important.";
            }
        }

        const RESOURCE_HEAP_TYPE resourceHeapType = GetResourceHeapType(
            newResourceDesc.Dimension, heapType, newResourceDesc.Flags, mResourceHeapTier);
        if (resourceHeapType == RESOURCE_HEAP_TYPE_INVALID) {
            ErrorLog(ErrorCode::kInvalidArgument, this)
                << "Unable to create resource allocation because the resource type was invalid due "
                   "to the combination of resource flags, descriptor, and resource heap tier.";
            return ErrorCode::kInvalidArgument;
        }

        // Resource is always committed when heaps flags are incompatible with the resource heap
        // type or if specified by the flag.
        bool isAlwaysCommitted = mIsAlwaysCommitted;

        // Check memory requirements.
        D3D12_HEAP_FLAGS heapFlags =
            GetHeapFlags(resourceHeapType, IsCreateHeapNotResidentEnabled());
        if (!HasAllFlags(heapFlags, allocationDescriptor.ExtraRequiredHeapFlags)) {
            WarnLog(MessageId::kPerformanceWarning, this)
                << "RESOURCE_ALLOCATOR_FLAG_ALWAYS_COMMITTED was not requested but enabled anyway "
                   "because "
                   "the required heap flags were incompatible with resource heap type ("
                << std::to_string(allocationDescriptor.ExtraRequiredHeapFlags) << " vs "
                << std::to_string(heapFlags) + ").";

            heapFlags |= allocationDescriptor.ExtraRequiredHeapFlags;

            // Fall-back to committed if resource heap is incompatible.
            // TODO: Considering adding resource heap types.
            isAlwaysCommitted = true;
        }

        bool isSubAllocationDisabled =
            allocationDescriptor.Flags & RESOURCE_ALLOCATION_FLAG_NEVER_SUBALLOCATE_HEAP;

        const bool isMSAA = newResourceDesc.SampleDesc.Count > 1;

        const bool isPaddingRequired = allocationDescriptor.ExtraRequiredResourcePadding > 0;

        // Attempt to allocate using the most effective allocator.
        MemoryAllocatorBase* allocator = nullptr;

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
            (allocationDescriptor.Flags & RESOURCE_ALLOCATION_FLAG_NEVER_ALLOCATE_HEAP);
        request.AlwaysPrefetch =
            (allocationDescriptor.Flags & RESOURCE_ALLOCATION_FLAG_ALWAYS_PREFETCH_HEAP);
        request.AlwaysCacheSize =
            (allocationDescriptor.Flags & RESOURCE_ALLOCATION_FLAG_ALWAYS_CACHE_SIZE);
        request.AvailableForAllocation = mMaxResourceHeapSize;

        // Apply extra padding to the resource heap size, if specified.
        // Padding can only be applied to standalone non-committed resources.
        if (GPGMM_UNLIKELY(isPaddingRequired)) {
            request.SizeInBytes += allocationDescriptor.ExtraRequiredResourcePadding;
            if (!isSubAllocationDisabled) {
                WarnLog(MessageId::kPerformanceWarning, this)
                    << "Sub-allocation was enabled but has no effect when padding is requested: "
                    << GetBytesToSizeInUnits(allocationDescriptor.ExtraRequiredResourcePadding)
                    << ".";
                isSubAllocationDisabled = true;
            }
        }

        D3D12_HEAP_PROPERTIES heapProperties =
            GetHeapProperties(mDevice, heapType, mIsCustomHeapsEnabled);

        const bool isUMA =
            (IsResidencyEnabled()) ? mResidencyManager->IsUMA() : mCaps->IsAdapterUMA();

        // Memory pool maps to the memory segment the allocation will belong to.
        // But since D3D12 requires the pool to be specified for the given heap type at
        // allocation-time, it must be set here and again, when a resource heap is created.
        heapProperties.MemoryPoolPreference = GetMemoryPool(heapProperties, isUMA);

        const DXGI_MEMORY_SEGMENT_GROUP heapSegment =
            GetHeapSegment(heapProperties.MemoryPoolPreference, isUMA);

        const uint64_t maxSegmentSize = mCaps->GetMaxSegmentSize(heapSegment);
        if (request.SizeInBytes > maxSegmentSize) {
            ErrorLog(ErrorCode::kSizeExceeded, this)
                << "Unable to create resource allocation because the resource size exceeded "
                   "the capabilities of the adapter: "
                << GetBytesToSizeInUnits(request.SizeInBytes) << " vs "
                << GetBytesToSizeInUnits(maxSegmentSize);
            return ErrorCode::kOutOfMemory;
        }

        // If the allocation must be created within the budget, restrict the amount of memory
        // to prevent OOM to free memory only or to the amount of budget left. The allocator
        // checks this amount to determine if its appropriate to pre-allocate more memory or
        // not.
        if (IsResidencyEnabled() && !IsCreateHeapNotResidentEnabled()) {
            DXGI_QUERY_VIDEO_MEMORY_INFO* currentVideoInfo =
                mResidencyManager->GetVideoMemoryInfo(heapSegment);

            // If over-budget, only free memory is considered available.
            // TODO: Consider optimizing GetStatsInternal().
            if (currentVideoInfo->CurrentUsage + request.SizeInBytes > currentVideoInfo->Budget) {
                const MemoryAllocatorStats allocationStats = GetStats();

                request.AvailableForAllocation = allocationStats.FreeMemoryUsage;

                DebugLog(MessageId::kBudgetExceeded, this)
                    << "Current usage exceeded budget: "
                    << GetBytesToSizeInUnits(currentVideoInfo->CurrentUsage) << " vs "
                    << GetBytesToSizeInUnits(currentVideoInfo->Budget) << " ("
                    << GetBytesToSizeInUnits(request.AvailableForAllocation) << " free).";

            } else {
                // Otherwise, only memory in budget is considered available.
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
        if (allocationDescriptor.Flags &
                RESOURCE_ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE &&
            resourceInfo.Alignment > newResourceDesc.Width &&
            newResourceDesc.Dimension == D3D12_RESOURCE_DIMENSION_BUFFER &&
            newResourceDesc.Flags == D3D12_RESOURCE_FLAG_NONE && isCreatedResourceStateRequired &&
            !isSubAllocationDisabled) {
            allocator = mSmallBufferAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();

            // GetResourceAllocationInfo() always rejects alignments smaller than 64KB. So if the
            // alignment was unspecified, assign the smallest alignment possible.
            MemoryAllocationRequest subAllocWithinRequest = request;
            if (resourceDescriptor.Alignment == 0) {
                // Only constant buffers must be 256B aligned.
                subAllocWithinRequest.Alignment =
                    (initialResourceState == D3D12_RESOURCE_STATE_GENERIC_READ)
                        ? D3D12_CONSTANT_BUFFER_DATA_PLACEMENT_ALIGNMENT
                        : UpperPowerOfTwo(newResourceDesc.Width);
            } else {
                subAllocWithinRequest.Alignment = resourceDescriptor.Alignment;
            }

            // Pre-fetching is not supported for resources since the pre-fetch thread must allocate
            // through |this| via CreateCommittedResource which is already locked by
            // CreateResource().
            subAllocWithinRequest.AlwaysPrefetch = false;

            GPGMM_RETURN_IF_NOT_FATAL(TryAllocateResource(
                allocator, subAllocWithinRequest, [&](const auto& subAllocation) -> HRESULT {
                    // Committed resource implicitly creates a resource heap which can be
                    // used for sub-allocation.
                    ComPtr<ID3D12Resource> committedResource;
                    ResidencyHeap* resourceHeap =
                        static_cast<ResidencyHeap*>(subAllocation.GetMemory());
                    GPGMM_RETURN_IF_FAILED(
                        resourceHeap->QueryInterface(IID_PPV_ARGS(&committedResource)), mDevice);

                    RESOURCE_RESOURCE_ALLOCATION_DESC allocationDesc = {};
                    allocationDesc.SizeInBytes = newResourceDesc.Width;
                    allocationDesc.HeapOffset = kInvalidOffset;
                    allocationDesc.Type = RESOURCE_ALLOCATION_TYPE_SUBALLOCATED_WITHIN;
                    allocationDesc.OffsetFromResource = subAllocation.GetOffset();
                    allocationDesc.DebugName = allocationDescriptor.DebugName;

                    *ppResourceAllocationOut = new ResourceAllocation(
                        allocationDesc, mResidencyManager.Get(), subAllocation.GetAllocator(),
                        resourceHeap, subAllocation.GetBlock(), std::move(committedResource));

                    return S_OK;
                }));
        }

        // Attempt to create a resource allocation by placing a resource in a sub-allocated
        // resource heap.
        // The time and space complexity of is determined by the sub-allocation algorithm used.
        if (!isAlwaysCommitted && !isSubAllocationDisabled) {
            if (isMSAA) {
                allocator =
                    mMSAAResourceAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();
            } else {
                allocator = mResourceAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();
            }

            MemoryAllocationRequest subAllocRequest = request;
            subAllocRequest.Alignment = resourceInfo.Alignment;

            GPGMM_RETURN_IF_NOT_FATAL(TryAllocateResource(
                allocator, subAllocRequest, [&](const auto& subAllocation) -> HRESULT {
                    // Resource is placed at an offset corresponding to the allocation offset.
                    // Each allocation maps to a disjoint (physical) address range so no physical
                    // memory is can be aliased or will overlap.
                    ComPtr<ID3D12Resource> placedResource;
                    ResidencyHeap* resourceHeap =
                        static_cast<ResidencyHeap*>(subAllocation.GetMemory());
                    GPGMM_RETURN_IF_FAILED(
                        CreatePlacedResource(resourceHeap, subAllocation.GetOffset(),
                                             &newResourceDesc, clearValue, initialResourceState,
                                             &placedResource),
                        mDevice);

                    RESOURCE_RESOURCE_ALLOCATION_DESC allocationDesc = {};
                    allocationDesc.SizeInBytes = subAllocRequest.SizeInBytes;
                    allocationDesc.HeapOffset = subAllocation.GetOffset();
                    allocationDesc.Type =
                        static_cast<RESOURCE_ALLOCATION_TYPE>(subAllocation.GetMethod());
                    allocationDesc.OffsetFromResource = 0;
                    allocationDesc.DebugName = allocationDescriptor.DebugName;

                    *ppResourceAllocationOut = new ResourceAllocation(
                        allocationDesc, mResidencyManager.Get(), subAllocation.GetAllocator(),
                        resourceHeap, subAllocation.GetBlock(), std::move(placedResource));

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
                    mMSAADedicatedResourceAllocatorOfType[static_cast<size_t>(resourceHeapType)]
                        .get();
            } else {
                allocator =
                    mDedicatedResourceAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();
            }

            MemoryAllocationRequest dedicatedRequest = request;
            dedicatedRequest.Alignment = allocator->GetMemoryAlignment();

            GPGMM_RETURN_IF_NOT_FATAL(TryAllocateResource(
                allocator, dedicatedRequest, [&](const auto& allocation) -> HRESULT {
                    ResidencyHeap* resourceHeap =
                        static_cast<ResidencyHeap*>(allocation.GetMemory());
                    ComPtr<ID3D12Resource> placedResource;
                    GPGMM_RETURN_IF_FAILED(
                        CreatePlacedResource(resourceHeap, allocation.GetOffset(), &newResourceDesc,
                                             clearValue, initialResourceState, &placedResource),
                        mDevice);

                    RESOURCE_RESOURCE_ALLOCATION_DESC allocationDesc = {};
                    allocationDesc.SizeInBytes = dedicatedRequest.SizeInBytes;
                    allocationDesc.HeapOffset = allocation.GetOffset();
                    allocationDesc.Type =
                        static_cast<RESOURCE_ALLOCATION_TYPE>(allocation.GetMethod());
                    allocationDesc.OffsetFromResource = 0;
                    allocationDesc.DebugName = allocationDescriptor.DebugName;

                    *ppResourceAllocationOut = new ResourceAllocation(
                        allocationDesc, mResidencyManager.Get(), allocation.GetAllocator(),
                        resourceHeap, allocation.GetBlock(), std::move(placedResource));

                    return S_OK;
                }));
        }

        // Attempt to create a standalone committed resource. This strategy is the safest but also
        // the most expensive so it's used as a last resort or if the developer needs larger
        // allocations where sub-allocation or pooling is otherwise ineffective.
        // The time and space complexity of committed resource is driver-defined.
        if (request.NeverAllocate) {
            ErrorLog(ErrorCode::kAllocationFailed, this)
                << "Unable to allocate memory for resource because no memory was could "
                   "be created and RESOURCE_ALLOCATION_FLAG_NEVER_ALLOCATE_HEAP was specified.";
            return ErrorCode::kAllocationFailed;
        }

        // Committed resources cannot specify resource heap size.
        if (GPGMM_UNLIKELY(isPaddingRequired)) {
            ErrorLog(ErrorCode::kAllocationFailed, this)
                << "Unable to allocate memory for resource because no memory was could "
                   "be created and ExtraRequiredResourcePadding was specified.";
            return ErrorCode::kAllocationFailed;
        }

        if (!isAlwaysCommitted) {
            if (allocationDescriptor.Flags & RESOURCE_ALLOCATION_FLAG_NEVER_FALLBACK) {
                ErrorLog(ErrorCode::kAllocationFailed, this)
                    << "Unable to allocate memory for resource because no memory was could "
                       "be created and RESOURCE_ALLOCATION_FLAG_NEVER_FALLBACK was specified.";
                return ErrorCode::kAllocationFailed;
            }
        }

        ComPtr<ID3D12Resource> committedResource;
        ComPtr<ResidencyHeap> resourceHeap;
        if (FAILED(CreateCommittedResource(heapProperties, heapFlags, resourceInfo,
                                           &newResourceDesc, clearValue, initialResourceState,
                                           &committedResource, &resourceHeap))) {
            return ErrorCode::kAllocationFailed;
        }

        if (resourceInfo.SizeInBytes > request.SizeInBytes) {
            WarnLog(MessageId::kPerformanceWarning, this)
                << "Resource heap is larger then the requested: "
                << GetBytesToSizeInUnits(resourceInfo.SizeInBytes) << " vs "
                << GetBytesToSizeInUnits(request.SizeInBytes) << ".";
        }

        // Using committed resources will create a tightly allocated resource allocations.
        // This means the block and heap size should be equal (modulo driver padding).
        const uint64_t& allocationSize = resourceHeap->GetSize();
        mStats.UsedMemoryUsage += allocationSize;
        mStats.UsedMemoryCount++;
        mStats.UsedBlockUsage += allocationSize;

        RESOURCE_RESOURCE_ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapOffset = kInvalidOffset;
        allocationDesc.SizeInBytes = request.SizeInBytes;
        allocationDesc.Type = RESOURCE_ALLOCATION_TYPE_STANDALONE;
        allocationDesc.DebugName = allocationDescriptor.DebugName;

        if (ppResourceAllocationOut != nullptr) {
            *ppResourceAllocationOut = new ResourceAllocation(
                allocationDesc, mResidencyManager.Get(), this, resourceHeap.Detach(), nullptr,
                std::move(committedResource));
        }

        return ErrorCode::kNone;
    }

    HRESULT ResourceAllocator::CreateResource(const RESOURCE_ALLOCATION_DESC& allocationDescriptor,
                                              ID3D12Resource* pCommittedResource,
                                              IResourceAllocation** ppResourceAllocationOut) {
        GPGMM_RETURN_IF_NULLPTR(pCommittedResource);

        std::lock_guard<std::mutex> lock(mMutex);

        D3D12_RESOURCE_DESC desc = pCommittedResource->GetDesc();
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo = GetResourceAllocationInfo(desc);

        D3D12_HEAP_PROPERTIES heapProperties;
        D3D12_HEAP_FLAGS heapFlags;
        GPGMM_RETURN_IF_FAILED(pCommittedResource->GetHeapProperties(&heapProperties, &heapFlags),
                               mDevice);

        // TODO: enable validation conditionally?
        if (allocationDescriptor.HeapType != 0 &&
            heapProperties.Type != allocationDescriptor.HeapType) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Unable to import a resource using a heap type that differs from the "
                   "heap type used at creation. For important resources, it is recommended "
                   "to not specify a heap type.";
            return GetErrorResult(ErrorCode::kInvalidArgument);
        }

        if (!HasAllFlags(heapFlags, allocationDescriptor.ExtraRequiredHeapFlags)) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Unable to import a resource using heap flags that differs from the "
                   "heap flags used at creation. For important resources, it is recommended "
                   "to not specify heap flags.";
            return GetErrorResult(ErrorCode::kInvalidArgument);
        }

        if (allocationDescriptor.ExtraRequiredResourcePadding > 0) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Unable to import a resource when using allocation flags which modify memory.";
            return GetErrorResult(ErrorCode::kInvalidArgument);
        }

        const RESOURCE_ALLOCATION_FLAGS allowMask =
            (RESOURCE_ALLOCATION_FLAG_NEVER_RESIDENT &
             RESOURCE_ALLOCATION_FLAG_ALWAYS_ATTRIBUTE_HEAPS &
             RESOURCE_ALLOCATION_FLAG_NEVER_ALLOCATE_HEAP);
        if (allocationDescriptor.Flags & ~allowMask) {
            ErrorLog(ErrorCode::kInvalidArgument)
                << "Unable to import a resource when using allocation flags which modify memory.";
            return GetErrorResult(ErrorCode::kInvalidArgument);
        }

        // If no resource allocation is to be created then only validate by returning early.
        if (ppResourceAllocationOut == nullptr) {
            return S_FALSE;
        }

        RESIDENCY_HEAP_DESC resourceHeapDesc = {};
        resourceHeapDesc.SizeInBytes = resourceInfo.SizeInBytes;
        resourceHeapDesc.Alignment = resourceInfo.Alignment;

        ImportResourceCallbackContext importResourceCallbackContext(pCommittedResource);

        ComPtr<IResidencyHeap> resourceHeap;
        GPGMM_RETURN_IF_FAILED(
            ResidencyHeap::CreateResidencyHeap(
                resourceHeapDesc,
                (allocationDescriptor.Flags & RESOURCE_ALLOCATION_FLAG_NEVER_RESIDENT)
                    ? nullptr
                    : mResidencyManager.Get(),
                ImportResourceCallbackContext::GetHeap, &importResourceCallbackContext,
                &resourceHeap),
            mDevice);

        const uint64_t& allocationSize = resourceInfo.SizeInBytes;
        mStats.UsedMemoryUsage += allocationSize;
        mStats.UsedMemoryCount++;
        mStats.UsedBlockUsage += allocationSize;

        RESOURCE_RESOURCE_ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapOffset = kInvalidSize;
        allocationDesc.SizeInBytes = allocationSize;
        allocationDesc.Type = RESOURCE_ALLOCATION_TYPE_STANDALONE;

        *ppResourceAllocationOut = new ResourceAllocation(
            allocationDesc, nullptr, this, static_cast<ResidencyHeap*>(resourceHeap.Detach()),
            nullptr, pCommittedResource);

        return S_OK;
    }

    HRESULT ResourceAllocator::CreatePlacedResource(ResidencyHeap* const resourceHeap,
                                                    uint64_t resourceOffset,
                                                    const D3D12_RESOURCE_DESC* resourceDescriptor,
                                                    const D3D12_CLEAR_VALUE* clearValue,
                                                    D3D12_RESOURCE_STATES initialResourceState,
                                                    ID3D12Resource** placedResourceOut) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResourceAllocator.CreatePlacedResource");

        // Before calling CreatePlacedResource, we must ensure the target heap is resident or
        // CreatePlacedResource will fail.
        ComPtr<ID3D12Resource> placedResource;
        {
            ComPtr<ID3D12Heap> heap;
            GPGMM_RETURN_IF_FAILED(resourceHeap->QueryInterface(IID_PPV_ARGS(&heap)), mDevice);

            ScopedResidencyLock residencyLock(mResidencyManager.Get(), resourceHeap);
            GPGMM_RETURN_IF_FAILED(
                mDevice->CreatePlacedResource(heap.Get(), resourceOffset, resourceDescriptor,
                                              initialResourceState, clearValue,
                                              IID_PPV_ARGS(&placedResource)),
                mDevice);
        }

        *placedResourceOut = placedResource.Detach();

        return S_OK;
    }

    HRESULT ResourceAllocator::CreateCommittedResource(
        D3D12_HEAP_PROPERTIES heapProperties,
        D3D12_HEAP_FLAGS heapFlags,
        const D3D12_RESOURCE_ALLOCATION_INFO& info,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* clearValue,
        D3D12_RESOURCE_STATES initialResourceState,
        ID3D12Resource** committedResourceOut,
        ResidencyHeap** resourceHeapOut) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResourceAllocator.CreateCommittedResource");

        RESIDENCY_HEAP_DESC resourceHeapDesc = {};
        resourceHeapDesc.SizeInBytes = info.SizeInBytes;
        resourceHeapDesc.Alignment = info.Alignment;
        resourceHeapDesc.DebugName = L"Resource heap (committed)";

        if (IsResidencyEnabled()) {
            resourceHeapDesc.Flags |= GetHeapFlags(heapFlags, mIsAlwaysCreatedInBudget);
            resourceHeapDesc.HeapSegment =
                GetHeapSegment(heapProperties.MemoryPoolPreference, mResidencyManager->IsUMA());
        }

        // Since residency is per heap, every committed resource is wrapped in a heap object.
        ComPtr<IResidencyHeap> resourceHeap;
        CreateCommittedResourceCallbackContext callbackContext(mDevice, &heapProperties, heapFlags,
                                                               resourceDescriptor, clearValue,
                                                               initialResourceState);

        GPGMM_RETURN_IF_FAILED(
            ResidencyHeap::CreateResidencyHeap(resourceHeapDesc, mResidencyManager.Get(),
                                               CreateCommittedResourceCallbackContext::CreateHeap,
                                               &callbackContext, &resourceHeap),
            mDevice);

        if (committedResourceOut != nullptr) {
            ComPtr<ID3D12Resource> committedResource;
            GPGMM_RETURN_IF_FAILED(resourceHeap.As(&committedResource), mDevice);

            *committedResourceOut = committedResource.Detach();
        }

        if (resourceHeapOut != nullptr) {
            *resourceHeapOut = static_cast<ResidencyHeap*>(resourceHeap.Detach());
        }

        return S_OK;
    }

    HRESULT ResourceAllocator::QueryStats(RESOURCE_ALLOCATOR_STATS* pResourceAllocatorStats) {
        std::lock_guard<std::mutex> lock(mMutex);
        const MemoryAllocatorStats result = GetStats();
        if (pResourceAllocatorStats != nullptr) {
            pResourceAllocatorStats->UsedBlockCount = result.UsedBlockCount;
            pResourceAllocatorStats->UsedBlockUsage = result.UsedBlockUsage;
            pResourceAllocatorStats->UsedHeapCount = result.UsedMemoryCount;
            pResourceAllocatorStats->UsedHeapUsage = result.UsedMemoryUsage;
            pResourceAllocatorStats->FreeHeapUsage = result.FreeMemoryUsage;
            pResourceAllocatorStats->PrefetchedHeapMisses = result.PrefetchedMemoryMisses;
            pResourceAllocatorStats->PrefetchedHeapMissesEliminated =
                result.PrefetchedMemoryMissesEliminated;
            pResourceAllocatorStats->SizeCacheMisses = result.SizeCacheMisses;
            pResourceAllocatorStats->SizeCacheHits = result.SizeCacheHits;
        } else {
            return S_FALSE;
        }
        return S_OK;
    }

    MemoryAllocatorStats ResourceAllocator::GetStats() const {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault, "ResourceAllocator.QueryStats");

        // ResourceAllocator itself could call CreateCommittedResource directly.
        MemoryAllocatorStats result = mStats;

        for (uint32_t resourceHeapTypeIndex = 0; resourceHeapTypeIndex < kNumOfResourceHeapTypes;
             resourceHeapTypeIndex++) {
            result += mSmallBufferAllocatorOfType[resourceHeapTypeIndex]->GetStats();

            result += mMSAADedicatedResourceAllocatorOfType[resourceHeapTypeIndex]->GetStats();
            result += mMSAAResourceAllocatorOfType[resourceHeapTypeIndex]->GetStats();

            result += mResourceAllocatorOfType[resourceHeapTypeIndex]->GetStats();
            result += mDedicatedResourceAllocatorOfType[resourceHeapTypeIndex]->GetStats();
        }

        // Dedicated allocations always have 1 block per heap so only check >1 blocks or when
        // sub-allocation is used.
        const uint64_t blocksPerHeap = SafeDivide(result.UsedBlockCount, result.UsedMemoryCount);
        if (blocksPerHeap > 1 && blocksPerHeap < kMinBlockToMemoryCountReportingThreshold) {
            WarnEvent(MessageId::kPerformanceWarning, this)
                << "Average number of resource allocations per heap is below threshold: "
                << blocksPerHeap << " blocks per heap (vs "
                << kMinBlockToMemoryCountReportingThreshold
                << "). This usually means the heap has insufficent space and "
                   "could beneifit from larger ResourceHeapGrowthFactor and/or "
                   "PreferredResourceHeapSize.";
        }

        const uint64_t allocationUsagePct =
            SafeDivide(result.UsedBlockUsage, result.UsedMemoryUsage + result.FreeMemoryUsage) *
            100;
        if (allocationUsagePct > 0 &&
            allocationUsagePct < kMinAllocationUsageReportingThreshold * 100) {
            WarnEvent(MessageId::kPerformanceWarning, this)
                << "Average resource allocation usage is below threshold: " << allocationUsagePct
                << "% vs " << uint64_t(kMinAllocationUsageReportingThreshold * 100)
                << "%. This either means memory has become fragmented or the working set has "
                   "changed significantly.";
        }

        GPGMM_TRACE_EVENT_METRIC("GPU allocation usage (%)", allocationUsagePct);

        GPGMM_TRACE_EVENT_METRIC("GPU allocation free (MB)",
                                 GPGMM_BYTES_TO_MB(result.FreeMemoryUsage));

        GPGMM_TRACE_EVENT_METRIC(
            "GPU allocation prefetch (%)",
            SafeDivide(result.PrefetchedMemoryMissesEliminated,
                       result.PrefetchedMemoryMisses + result.PrefetchedMemoryMissesEliminated) *
                100);

        GPGMM_TRACE_EVENT_METRIC(
            "GPU allocation cache-hits (%)",
            SafeDivide(result.SizeCacheHits, result.SizeCacheMisses + result.SizeCacheHits) * 100);

        return result;
    }

    HRESULT ResourceAllocator::ReportLiveDeviceObjects() const {
        // Debug layer was never enabled.
        ComPtr<ID3D12DebugDevice> debugDevice;
        if (FAILED(mDevice->QueryInterface(IID_PPV_ARGS(&debugDevice)))) {
            return S_OK;
        }

        const D3D12_RLDO_FLAGS rldoFlags = D3D12_RLDO_DETAIL | D3D12_RLDO_IGNORE_INTERNAL;
        GPGMM_RETURN_IF_FAILED(debugDevice->ReportLiveDeviceObjects(rldoFlags), mDevice);

        ComPtr<ID3D12InfoQueue> leakMessageQueue;
        GPGMM_RETURN_IF_FAILED(mDevice->QueryInterface(IID_PPV_ARGS(&leakMessageQueue)), mDevice);

        // Report live device objects that could be created by GPGMM by checking the global filter.
        // This is because the allowList filter cannot easily be made exclusive to these IDs.
        for (uint64_t i = 0; i < leakMessageQueue->GetNumStoredMessagesAllowedByRetrievalFilter();
             ++i) {
            SIZE_T messageLength = 0;
            GPGMM_RETURN_IF_FAILED(leakMessageQueue->GetMessage(i, nullptr, &messageLength),
                                   mDevice);

            std::unique_ptr<uint8_t[]> messageData(new uint8_t[messageLength]);
            D3D12_MESSAGE* message = reinterpret_cast<D3D12_MESSAGE*>(messageData.get());
            GPGMM_RETURN_IF_FAILED(leakMessageQueue->GetMessage(i, message, &messageLength),
                                   mDevice);

            switch (message->ID) {
                case D3D12_MESSAGE_ID_LIVE_HEAP:
                case D3D12_MESSAGE_ID_LIVE_RESOURCE: {
                    WarnLog(MessageId::kPerformanceWarning, this)
                        << "Device leak detected: " + std::string(message->pDescription);
                } break;
                default:
                    break;
            }
        }

        leakMessageQueue->PopRetrievalFilter();
        return S_OK;
    }

    void ResourceAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) {
        GPGMM_TRACE_EVENT_DURATION(TraceEventCategory::kDefault,
                                   "ResourceAllocator.DeallocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        const uint64_t& allocationSize = allocation->GetSize();
        mStats.UsedMemoryUsage -= allocationSize;
        mStats.UsedMemoryCount--;
        mStats.UsedBlockUsage -= allocationSize;

        SafeRelease(allocation);
    }

    bool ResourceAllocator::IsCreateHeapNotResidentEnabled() const {
        return IsResidencyEnabled() && mIsCreateNotResidentEnabled;
    }

    bool ResourceAllocator::IsResidencyEnabled() const {
        return mResidencyManager != nullptr;
    }

    HRESULT ResourceAllocator::CheckFeatureSupport(RESOURCE_ALLOCATOR_FEATURE feature,
                                                   void* pFeatureSupportData,
                                                   uint32_t featureSupportDataSize) const {
        switch (feature) {
            case RESOURCE_ALLOCATOR_FEATURE_RESOURCE_ALLOCATION_SUPPORT: {
                FEATURE_DATA_RESOURCE_ALLOCATION_SUPPORT data = {};
                if (featureSupportDataSize != sizeof(data)) {
                    return E_INVALIDARG;
                }
                data.IsResourceAllocationWithinCoherent =
                    mCaps->IsResourceAllocationWithinCoherent();
                FEATURE_DATA_RESOURCE_ALLOCATION_SUPPORT* pFeatureData =
                    static_cast<FEATURE_DATA_RESOURCE_ALLOCATION_SUPPORT*>(pFeatureSupportData);
                memcpy_s(pFeatureData, featureSupportDataSize, &data, sizeof(data));
                return S_OK;
            }
            default: {
                ErrorLog(ErrorCode::kInvalidArgument, this)
                    << "CheckFeatureSupport does not support feature (" + std::to_string(feature) +
                           ").";
                return GetErrorResult(ErrorCode::kInvalidArgument);
            }
        }

        return E_INVALIDARG;
    }

    LPCWSTR ResourceAllocator::GetDebugName() const {
        return DebugObject::GetDebugName();
    }

    HRESULT ResourceAllocator::SetDebugName(LPCWSTR Name) {
        return DebugObject::SetDebugNameImpl(Name);
    }

    ImportResourceCallbackContext::ImportResourceCallbackContext(ID3D12Resource* resource)
        : mResource(resource) {
    }

    // static
    HRESULT ImportResourceCallbackContext::GetHeap(void* pContext, ID3D12Pageable** ppPageableOut) {
        return static_cast<ImportResourceCallbackContext*>(pContext)->GetHeap(ppPageableOut);
    }

    HRESULT ImportResourceCallbackContext::GetHeap(ID3D12Pageable** ppPageableOut) {
        return mResource->QueryInterface(IID_PPV_ARGS(ppPageableOut));
    }

    CreateCommittedResourceCallbackContext::CreateCommittedResourceCallbackContext(
        ID3D12Device* device,
        D3D12_HEAP_PROPERTIES* heapProperties,
        D3D12_HEAP_FLAGS heapFlags,
        const D3D12_RESOURCE_DESC* resourceDescriptor,
        const D3D12_CLEAR_VALUE* clearValue,
        D3D12_RESOURCE_STATES initialResourceState)
        : mClearValue(clearValue),
          mDevice(device),
          mInitialResourceState(initialResourceState),
          mHeapFlags(heapFlags),
          mHeapProperties(heapProperties),
          mResourceDescriptor(resourceDescriptor) {
    }

    // static
    HRESULT CreateCommittedResourceCallbackContext::CreateHeap(void* pContext,
                                                               ID3D12Pageable** ppPageableOut) {
        CreateCommittedResourceCallbackContext* createCommittedResourceCallbackContext =
            static_cast<CreateCommittedResourceCallbackContext*>(pContext);

        return createCommittedResourceCallbackContext->CreateCommittedResource(ppPageableOut);
    }

    HRESULT CreateCommittedResourceCallbackContext::CreateCommittedResource(
        ID3D12Pageable** ppPageableOut) {
        // Resource heap flags must be inferred by the resource descriptor and cannot be
        // explicitly provided to CreateCommittedResource.
        mHeapFlags &= ~(D3D12_HEAP_FLAG_DENY_NON_RT_DS_TEXTURES |
                        D3D12_HEAP_FLAG_DENY_RT_DS_TEXTURES | D3D12_HEAP_FLAG_DENY_BUFFERS);

        // Non-custom heaps are not allowed to have the pool-specified.
        if (mHeapProperties->Type != D3D12_HEAP_TYPE_CUSTOM) {
            mHeapProperties->MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
        }

        ComPtr<ID3D12Resource> committedResource;
        GPGMM_RETURN_IF_FAILED(
            mDevice->CreateCommittedResource(mHeapProperties, mHeapFlags, mResourceDescriptor,
                                             mInitialResourceState, mClearValue,
                                             IID_PPV_ARGS(&committedResource)),
            mDevice);

        *ppPageableOut = committedResource.Detach();
        return S_OK;
    }

}  // namespace gpgmm::d3d12
