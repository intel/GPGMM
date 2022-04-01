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
#include "gpgmm/MemorySize.h"
#include "gpgmm/SegmentedMemoryAllocator.h"
#include "gpgmm/SlabMemoryAllocator.h"
#include "gpgmm/common/Math.h"
#include "gpgmm/common/Utils.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/BufferAllocatorD3D12.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/DebugD3D12.h"
#include "gpgmm/d3d12/DebugResourceAllocatorD3D12.h"
#include "gpgmm/d3d12/DefaultsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
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
                return {
                    AlignTo(resourceDescriptor.Width, D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT),
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
                LogSeverity severity = LogSeverity::Debug;
#ifdef GPGMM_ENABLE_D3D12_RESOURCE_ALIGNMENT_WARNING
                severity = LogSeverity::Warning;
#endif
                RecordMessage(severity, "ResourceAllocator.GetResourceAllocationInfo",
                              "Resource alignment is much larger due to D3D12 (" +
                                  std::to_string(resourceDescriptor.Alignment) + " vs " +
                                  std::to_string(resourceInfo.Alignment) +
                                  " bytes) for resource : " +
                                  JSONSerializer::Serialize(resourceDescriptor).ToString() + ".",
                              ALLOCATOR_MESSAGE_ID_RESOURCE_MISALIGNMENT);

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
        class ScopedHeapLock final : public NonCopyable {
          public:
            ScopedHeapLock(ResidencyManager* const residencyManager, Heap* const heap)
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
                                    bool cacheSize,
                                    CreateResourceFn&& createResourceFn) {
            std::unique_ptr<MemoryAllocation> allocation =
                allocator->TryAllocateMemory(size, alignment, neverAllocate, cacheSize);
            if (allocation == nullptr) {
                RecordMessage(LogSeverity::Debug, "ResourceAllocator.TryAllocateResource",
                              "Resource memory could not be allocated.",
                              ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_FAILED);
                return E_FAIL;
            }
            HRESULT hr = createResourceFn(*allocation);
            if (FAILED(hr)) {
                RecordMessage(LogSeverity::Debug, "ResourceAllocator.TryAllocateResource",
                              "Resource failed to be created: " + GetErrorMessage(hr),
                              ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_FAILED);
                allocator->DeallocateMemory(std::move(allocation));
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

        std::unique_ptr<Caps> caps;
        {
            Caps* ptr = nullptr;
            ReturnIfFailed(
                Caps::CreateCaps(descriptor.Device.Get(), descriptor.Adapter.Get(), &ptr));
            caps.reset(ptr);
        }

        ALLOCATOR_DESC newDescriptor = descriptor;
        newDescriptor.PreferredResourceHeapSize = (descriptor.PreferredResourceHeapSize > 0)
                                                      ? descriptor.PreferredResourceHeapSize
                                                      : kDefaultPreferredResourceHeapSize;

        newDescriptor.MaxResourceHeapSize =
            (descriptor.MaxResourceHeapSize > 0)
                ? std::min(descriptor.MaxResourceHeapSize, caps->GetMaxResourceHeapSize())
                : caps->GetMaxResourceHeapSize();

        newDescriptor.ResourceFragmentationLimit = (descriptor.ResourceFragmentationLimit > 0)
                                                       ? descriptor.ResourceFragmentationLimit
                                                       : kDefaultFragmentationLimit;

        if (newDescriptor.PreferredResourceHeapSize > newDescriptor.MaxResourceHeapSize) {
            return E_INVALIDARG;
        }

        if (newDescriptor.MaxResourceSizeForPooling > 0 &&
            newDescriptor.MaxResourceSizeForPooling > newDescriptor.MaxResourceHeapSize) {
            return E_INVALIDARG;
        }

#ifdef GPGMM_ALWAYS_RECORD
        newDescriptor.RecordOptions.Flags |= ALLOCATOR_RECORD_FLAG_ALL_EVENTS;
#endif

        if (newDescriptor.RecordOptions.Flags != ALLOCATOR_RECORD_FLAG_NONE) {
            const std::string& traceFile = descriptor.RecordOptions.TraceFile.empty()
                                               ? std::string(kDefaultTraceFile)
                                               : descriptor.RecordOptions.TraceFile;

            StartupEventTracer(
                traceFile, !(newDescriptor.RecordOptions.Flags & ALLOCATOR_RECORD_FLAG_API_TIMINGS),
                !(newDescriptor.RecordOptions.Flags & ALLOCATOR_RECORD_FLAG_API_OBJECTS),
                !(newDescriptor.RecordOptions.Flags & ALLOCATOR_RECORD_FLAG_API_CALLS));

            const LogSeverity& recordMessageMinLevel =
                static_cast<LogSeverity>(newDescriptor.RecordOptions.MinMessageLevel);

            SetRecordMessageLevel(recordMessageMinLevel);
        }

        const LogSeverity& logLevel = static_cast<LogSeverity>(newDescriptor.MinLogLevel);
        SetLogMessageLevel(logLevel);

        ComPtr<ResidencyManager> residencyManager;
        if (residencyManagerOut != nullptr) {
            ReturnIfFailed(ResidencyManager::CreateResidencyManager(
                newDescriptor.Device, newDescriptor.Adapter, newDescriptor.IsUMA,
                newDescriptor.MaxVideoMemoryBudget, newDescriptor.TotalResourceBudgetLimit,
                newDescriptor.VideoMemoryEvictSize, &residencyManager));
        }

        *resourceAllocatorOut =
            new ResourceAllocator(newDescriptor, residencyManager, std::move(caps));

        if (residencyManagerOut != nullptr) {
            *residencyManagerOut = residencyManager.Detach();
        }

        return S_OK;
    }

    ResourceAllocator::ResourceAllocator(const ALLOCATOR_DESC& descriptor,
                                         ComPtr<ResidencyManager> residencyManager,
                                         std::unique_ptr<Caps> caps)
        : mDevice(std::move(descriptor.Device)),
          mResidencyManager(std::move(residencyManager)),
          mCaps(std::move(caps)),
          mIsUMA(descriptor.IsUMA),
          mResourceHeapTier(descriptor.ResourceHeapTier),
          mIsAlwaysCommitted(descriptor.Flags & ALLOCATOR_FLAG_ALWAYS_COMMITED),
          mIsAlwaysInBudget(descriptor.Flags & ALLOCATOR_FLAG_ALWAYS_IN_BUDGET),
          mMaxResourceHeapSize(descriptor.MaxResourceHeapSize),
          mMaxResourceSizeForPooling(descriptor.MaxResourceSizeForPooling) {
        TRACE_EVENT_OBJECT_CREATED_WITH_ID(TraceEventCategory::Default, "GPUMemoryAllocator", this);
        d3d12::RecordObject("GPUMemoryAllocator", this, descriptor);

        if (descriptor.Flags & ALLOCATOR_FLAG_CHECK_DEVICE_LEAKS &&
            FAILED(EnableDeviceObjectLeakChecks())) {
            gpgmm::WarningLog() << "Debug layers must be enabled to use device leak checking.\n";
        }

#if defined(GPGMM_ENABLE_PRECISE_ALLOCATOR_DEBUG)
        mDebugAllocator = std::make_unique<DebugResourceAllocator>();
#endif

        for (uint32_t resourceHeapTypeIndex = 0; resourceHeapTypeIndex < kNumOfResourceHeapTypes;
             resourceHeapTypeIndex++) {
            const RESOURCE_HEAP_TYPE& resourceHeapType =
                static_cast<RESOURCE_HEAP_TYPE>(resourceHeapTypeIndex);

            const D3D12_HEAP_FLAGS& heapFlags = GetHeapFlags(resourceHeapType);
            const uint64_t& heapAlignment = GetHeapAlignment(heapFlags);
            const D3D12_HEAP_TYPE& heapType = GetHeapType(resourceHeapType);

            // General-purpose allocators.
            // Used for dynamic resource allocation or when the resource size is not known at
            // compile-time.
            {
                std::unique_ptr<MemoryAllocator> standaloneAllocator =
                    std::make_unique<ResourceHeapAllocator>(this, heapType, heapFlags);

                std::unique_ptr<MemoryAllocator> pooledHeapAllocator =
                    std::make_unique<SegmentedMemoryAllocator>(
                        std::make_unique<ResourceHeapAllocator>(this, heapType, heapFlags),
                        heapAlignment);

                std::unique_ptr<MemoryAllocator> conditionalHeapAllocator =
                    std::make_unique<ConditionalMemoryAllocator>(std::move(pooledHeapAllocator),
                                                                 std::move(standaloneAllocator),
                                                                 mMaxResourceSizeForPooling);

                std::unique_ptr<MemoryAllocator> buddySubAllocator =
                    std::make_unique<BuddyMemoryAllocator>(
                        PrevPowerOfTwo(mMaxResourceHeapSize), descriptor.PreferredResourceHeapSize,
                        heapAlignment, std::move(conditionalHeapAllocator));

                // TODO: Figure out the optimal slab size to heap ratio.
                mResourceAllocatorOfType[resourceHeapTypeIndex] =
                    std::make_unique<SlabCacheAllocator>(
                        D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                        PrevPowerOfTwo(mMaxResourceHeapSize), descriptor.PreferredResourceHeapSize,
                        heapAlignment, descriptor.ResourceFragmentationLimit,
                        std::move(buddySubAllocator));
            }

            {
                std::unique_ptr<MemoryAllocator> standaloneAllocator =
                    std::make_unique<ResourceHeapAllocator>(this, heapType, heapFlags);

                std::unique_ptr<MemoryAllocator> pooledHeapAllocator =
                    std::make_unique<SegmentedMemoryAllocator>(
                        std::make_unique<ResourceHeapAllocator>(this, heapType, heapFlags),
                        heapAlignment);

                mResourceHeapAllocatorOfType[resourceHeapTypeIndex] =
                    std::make_unique<ConditionalMemoryAllocator>(std::move(pooledHeapAllocator),
                                                                 std::move(standaloneAllocator),
                                                                 mMaxResourceSizeForPooling);
            }

            // Dedicated allocators.
            {
                // Buffers are always 64KB aligned.
                // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_resource_desc
                std::unique_ptr<MemoryAllocator> bufferOnlyAllocator =
                    std::make_unique<BufferAllocator>(
                        this, heapType, D3D12_RESOURCE_FLAG_NONE, GetInitialResourceState(heapType),
                        /*resourceSize*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*resourceAlignment*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT);

                std::unique_ptr<MemoryAllocator> pooledBufferOnlyAllocator =
                    std::make_unique<SegmentedMemoryAllocator>(
                        std::make_unique<BufferAllocator>(
                            this, heapType, D3D12_RESOURCE_FLAG_NONE,
                            GetInitialResourceState(heapType),
                            /*resourceSize*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                            /*resourceAlignment*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT),
                        /*heapAlignment*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT);

                std::unique_ptr<MemoryAllocator> pooledOrNonPooledBufferAllocator =
                    std::make_unique<ConditionalMemoryAllocator>(
                        std::move(bufferOnlyAllocator), std::move(pooledBufferOnlyAllocator),
                        mMaxResourceSizeForPooling);

                // Buffers are byte-addressable when sub-allocated within and cannot internally
                // fragment by definition.
                mBufferAllocatorOfType[resourceHeapTypeIndex] =
                    std::make_unique<SlabCacheAllocator>(
                        /*minBlockSize*/ 1,
                        /*maxSlabSize*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*slabSize*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*slabAlignment*/ D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*slabFragmentationLimit*/ 0, std::move(pooledOrNonPooledBufferAllocator));
            }

            // Cache resource sizes commonly requested.
            // Ensures the next block is always made available upon first request without
            // increasing the memory footprint. Since resources are always sized-aligned, the
            // cached size must be requested per alignment {4KB, 64KB, or 4MB}. To avoid unbounded
            // cache growth, a known set of pre-defined sizes initializes the allocators.

#if defined(GPGMM_ENABLE_SIZE_CACHE)
            // Temporary suppress log messages emitted from internal cache-miss requests.
            {
                ScopedLogLevel scopedLogLevel(LogSeverity::Info);
                for (uint64_t i = 0; i < MemorySize::kPowerOfTwoClassSize; i++) {
                    mResourceAllocatorOfType[resourceHeapTypeIndex]->TryAllocateMemory(
                        MemorySize::kPowerOfTwoCacheSizes[i].SizeInBytes,
                        D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*neverAllocate*/ true, /*cacheSize*/ true);

                    mResourceAllocatorOfType[resourceHeapTypeIndex]->TryAllocateMemory(
                        MemorySize::kPowerOfTwoCacheSizes[i].SizeInBytes,
                        D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*neverAllocate*/ true, /*cacheSize*/ true);

                    mResourceAllocatorOfType[resourceHeapTypeIndex]->TryAllocateMemory(
                        MemorySize::kPowerOfTwoCacheSizes[i].SizeInBytes,
                        D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT,
                        /*neverAllocate*/ true, /*cacheSize*/ true);
                }
            }
#endif
        }
    }

    ResourceAllocator::~ResourceAllocator() {
        TRACE_EVENT_OBJECT_DELETED_WITH_ID(TraceEventCategory::Default, "GPUMemoryAllocator", this);

        // Destroy allocators in the reverse order they were created so we can record delete events
        // before event tracer shutdown.
        mBufferAllocatorOfType = {};
        mResourceAllocatorOfType = {};
        mResourceHeapAllocatorOfType = {};

        ShutdownEventTracer();

#if defined(GPGMM_ENABLE_PRECISE_ALLOCATOR_DEBUG)
        mDebugAllocator->ReportLiveAllocations();
#endif

        ASSERT(SUCCEEDED(CheckForDeviceObjectLeaks()));
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

        RecordCall<CREATE_RESOURCE_DESC>("ResourceAllocator.CreateResource", allocationDescriptor,
                                         resourceDescriptor, initialResourceState, clearValue);

        TRACE_EVENT_CALL_SCOPED(TraceEventCategory::Default, "ResourceAllocator.CreateResource");

        ReturnIfFailed(CreateResourceInternal(allocationDescriptor, resourceDescriptor,
                                              initialResourceState, clearValue,
                                              resourceAllocationOut));

        // Insert a new (debug) allocator layer into the allocation so it can report details used
        // during leak checks. Since we don't want to use it unless we are debugging, we hide it
        // behind a macro.
#if defined(GPGMM_ENABLE_PRECISE_ALLOCATOR_DEBUG)
        mDebugAllocator->AddLiveAllocation(*resourceAllocationOut);
#endif
        return S_OK;
    }

    HRESULT ResourceAllocator::CreateResourceInternal(const ALLOCATION_DESC& allocationDescriptor,
                                                      const D3D12_RESOURCE_DESC& resourceDescriptor,
                                                      D3D12_RESOURCE_STATES initialResourceState,
                                                      const D3D12_CLEAR_VALUE* clearValue,
                                                      ResourceAllocation** resourceAllocationOut) {
        // If d3d tells us the resource size is invalid, treat the error as OOM.
        // Otherwise, creating a very large resource could overflow the allocator.
        D3D12_RESOURCE_DESC newResourceDesc = resourceDescriptor;
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), newResourceDesc);
        if (resourceInfo.SizeInBytes == kInvalidSize) {
            return E_OUTOFMEMORY;
        }

        if (resourceInfo.SizeInBytes > mMaxResourceHeapSize ||
            resourceInfo.SizeInBytes > mCaps->GetMaxResourceSize()) {
            return E_OUTOFMEMORY;
        }

        const RESOURCE_HEAP_TYPE resourceHeapType =
            GetResourceHeapType(newResourceDesc.Dimension, allocationDescriptor.HeapType,
                                newResourceDesc.Flags, mResourceHeapTier);
        if (resourceHeapType == RESOURCE_HEAP_TYPE_INVALID) {
            return E_INVALIDARG;
        }

        const bool neverAllocate =
            allocationDescriptor.Flags & ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;

        const bool neverSubAllocate =
            allocationDescriptor.Flags & ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;

        // Attempt to allocate using the most effective allocator.;
        MemoryAllocator* allocator = nullptr;

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
            !mIsAlwaysCommitted && !neverSubAllocate) {
            allocator = mBufferAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();

            const uint64_t alignment =
                (newResourceDesc.Alignment == 0) ? 1 : newResourceDesc.Alignment;

            ReturnIfSucceeded(TryAllocateResource(
                allocator, newResourceDesc.Width, alignment, neverAllocate,
                /*cacheSize*/ false, [&](const auto& subAllocation) -> HRESULT {
                    // Committed resource implicitly creates a resource heap which can be
                    // used for sub-allocation.
                    ComPtr<ID3D12Resource> committedResource;
                    Heap* resourceHeap = ToBackend(subAllocation.GetMemory());
                    ReturnIfFailed(resourceHeap->GetPageable().As(&committedResource));

                    *resourceAllocationOut = new ResourceAllocation{
                        mResidencyManager.Get(),      subAllocation.GetAllocator(),
                        subAllocation.GetBlock(),     subAllocation.GetOffset(),
                        std::move(committedResource), resourceHeap};

                    if (subAllocation.GetSize() > newResourceDesc.Width) {
                        RecordMessage(
                            LogSeverity::Debug, "ResourceAllocator.CreateResource",
                            "Resource allocation size is larger then the resource size (" +
                                std::to_string(subAllocation.GetSize()) + " vs " +
                                std::to_string(newResourceDesc.Width) + " bytes).",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_MISALIGNMENT);
                    }

                    return S_OK;
                }));
        }

        // Attempt to create a resource allocation by placing a resource in a sub-allocated
        // resource heap.
        // The time and space complexity of is determined by the sub-allocation algorithm used.
        if (!mIsAlwaysCommitted && !neverSubAllocate) {
            allocator = mResourceAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();

            ReturnIfSucceeded(TryAllocateResource(
                allocator, resourceInfo.SizeInBytes, resourceInfo.Alignment, neverAllocate,
                /*cacheSize*/ false, [&](const auto& subAllocation) -> HRESULT {
                    // Resource is placed at an offset corresponding to the allocation offset.
                    // Each allocation maps to a disjoint (physical) address range so no physical
                    // memory is can be aliased or will overlap.
                    ComPtr<ID3D12Resource> placedResource;
                    Heap* resourceHeap = ToBackend(subAllocation.GetMemory());
                    ReturnIfFailed(CreatePlacedResource(resourceHeap, subAllocation.GetOffset(),
                                                        &newResourceDesc, clearValue,
                                                        initialResourceState, &placedResource));

                    *resourceAllocationOut = new ResourceAllocation{
                        mResidencyManager.Get(),   subAllocation.GetAllocator(),
                        subAllocation.GetOffset(), subAllocation.GetBlock(),
                        std::move(placedResource), resourceHeap};

                    if (subAllocation.GetSize() > resourceInfo.SizeInBytes) {
                        RecordMessage(
                            LogSeverity::Debug, "ResourceAllocator.CreateResource",
                            "Resource allocation size is larger then the resource size (" +
                                std::to_string(subAllocation.GetSize()) + " vs " +
                                std::to_string(resourceInfo.SizeInBytes) + " bytes).",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_MISALIGNMENT);
                    }

                    return S_OK;
                }));
        }

        const D3D12_HEAP_FLAGS& heapFlags = GetHeapFlags(resourceHeapType);

        // Attempt to create a resource allocation by placing a single resource fully contained
        // in a resource heap. This strategy is slightly better then creating a committed
        // resource because a placed resource's heap will not be reallocated by the OS until Trim()
        // is called.
        // The time and space complexity is determined by the allocator type.
        if (!mIsAlwaysCommitted && mMaxResourceSizeForPooling != 0) {
            allocator = mResourceHeapAllocatorOfType[static_cast<size_t>(resourceHeapType)].get();

            ReturnIfSucceeded(TryAllocateResource(
                allocator, resourceInfo.SizeInBytes, GetHeapAlignment(heapFlags), neverAllocate,
                /*cacheSize*/ false, [&](const auto& allocation) -> HRESULT {
                    Heap* resourceHeap = ToBackend(allocation.GetMemory());
                    ComPtr<ID3D12Resource> placedResource;
                    ReturnIfFailed(CreatePlacedResource(resourceHeap, allocation.GetOffset(),
                                                        &newResourceDesc, clearValue,
                                                        initialResourceState, &placedResource));

                    *resourceAllocationOut = new ResourceAllocation{
                        mResidencyManager.Get(), allocation.GetAllocator(),
                        /*offsetFromHeap*/ 0, std::move(placedResource), resourceHeap};

                    if (allocation.GetSize() > resourceInfo.SizeInBytes) {
                        RecordMessage(
                            LogSeverity::Debug, "ResourceAllocator.CreateResource",
                            "Resource allocation size is larger then the resource size (" +
                                std::to_string(allocation.GetSize()) + " vs " +
                                std::to_string(resourceInfo.SizeInBytes) + " bytes).",
                            ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_MISALIGNMENT);
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
            RecordMessage(LogSeverity::Debug, "ResourceAllocator.CreateResource",
                          "Resource allocation could not be created from memory pool.",
                          ALLOCATOR_MESSAGE_ID_RESOURCE_ALLOCATION_NON_POOLED);
        }

        ComPtr<ID3D12Resource> committedResource;
        Heap* resourceHeap = nullptr;
        ReturnIfFailed(CreateCommittedResource(
            allocationDescriptor.HeapType, heapFlags, resourceInfo.SizeInBytes, &newResourceDesc,
            clearValue, initialResourceState, &committedResource, &resourceHeap));

        *resourceAllocationOut =
            new ResourceAllocation{mResidencyManager.Get(), this, /*offsetFromHeap*/ kInvalidOffset,
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
        const D3D12_RESOURCE_ALLOCATION_INFO resourceInfo =
            GetResourceAllocationInfo(mDevice.Get(), desc);

        D3D12_HEAP_PROPERTIES heapProperties;
        ReturnIfFailed(resource->GetHeapProperties(&heapProperties, nullptr));

        Heap* resourceHeap = new Heap(
            resource, GetPreferredMemorySegmentGroup(mDevice.Get(), mIsUMA, heapProperties.Type),
            resourceInfo.SizeInBytes);

        *resourceAllocationOut =
            new ResourceAllocation{/*residencyManager*/ nullptr,
                                   /*allocator*/ this, /*offsetFromHeap*/ kInvalidOffset,
                                   std::move(resource), resourceHeap};

        return S_OK;
    }

    HRESULT ResourceAllocator::CreatePlacedResource(Heap* const resourceHeap,
                                                    uint64_t resourceOffset,
                                                    const D3D12_RESOURCE_DESC* resourceDescriptor,
                                                    const D3D12_CLEAR_VALUE* clearValue,
                                                    D3D12_RESOURCE_STATES initialResourceState,
                                                    ID3D12Resource** placedResourceOut) {
        ASSERT(resourceHeap != nullptr);

        TRACE_EVENT_CALL_SCOPED(TraceEventCategory::Default,
                                "ResourceAllocator.CreatePlacedResource");

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
        TRACE_EVENT_CALL_SCOPED(TraceEventCategory::Default,
                                "ResourceAllocator.CreateResourceHeap");

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

        ComPtr<ID3D12Heap> heap;
        ReturnIfFailed(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap)));

        Heap* resourceHeap = new Heap(std::move(heap), memorySegmentGroup, heapSize);

        // Calling CreateHeap implicitly calls MakeResident on the new heap. We must track this to
        // avoid calling MakeResident a second time.
        if (mResidencyManager != nullptr) {
            mResidencyManager->InsertHeap(resourceHeap);
        }

        mInfo.UsedMemoryUsage += heapSize;
        mInfo.UsedMemoryCount++;

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
        TRACE_EVENT_CALL_SCOPED(TraceEventCategory::Default,
                                "ResourceAllocator.CreateCommittedResource");

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

        mInfo.UsedMemoryUsage += resourceHeap->GetSize();
        mInfo.UsedMemoryCount++;

        *resourceHeapOut = resourceHeap;

        return S_OK;
    }

    ResidencyManager* ResourceAllocator::GetResidencyManager() const {
        return mResidencyManager.Get();
    }

    HRESULT ResourceAllocator::QueryResourceAllocatorInfo(
        QUERY_RESOURCE_ALLOCATOR_INFO* resourceAllocationInfoOut) const {
        TRACE_EVENT_CALL_SCOPED(TraceEventCategory::Default,
                                "ResourceAllocator.QueryResourceAllocatorInfo");

        MEMORY_ALLOCATOR_INFO infoOut = {};
        for (const auto& allocator : mResourceAllocatorOfType) {
            const MEMORY_ALLOCATOR_INFO& info = allocator->QueryInfo();
            infoOut.UsedBlockCount += info.UsedBlockCount;
            infoOut.UsedBlockUsage += info.UsedBlockUsage;
        }

        for (const auto& allocator : mBufferAllocatorOfType) {
            const MEMORY_ALLOCATOR_INFO& info = allocator->QueryInfo();
            infoOut.UsedBlockCount += info.UsedBlockCount;
            infoOut.UsedBlockUsage += info.UsedBlockUsage;
        }

        // Only ResourceAllocator can create/destroy resource heaps.
        infoOut.UsedMemoryUsage = mInfo.UsedMemoryUsage;
        infoOut.UsedMemoryCount = mInfo.UsedMemoryCount;

        for (const auto& allocator : mResourceHeapAllocatorOfType) {
            const MEMORY_ALLOCATOR_INFO& info = allocator->QueryInfo();
            infoOut.FreeMemoryUsage += info.FreeMemoryUsage;
        }

        gpgmm::RecordObject("GPUMemoryAllocator", this, infoOut);

        if (resourceAllocationInfoOut != nullptr) {
            *resourceAllocationInfoOut = infoOut;
        }

        return S_OK;
    }

    // Returns error HR if the debug layer is not available.
    HRESULT ResourceAllocator::EnableDeviceObjectLeakChecks() const {
        ComPtr<ID3D12InfoQueue> leakMessageQueue;
        ReturnIfFailed(mDevice.As(&leakMessageQueue));

        D3D12_INFO_QUEUE_FILTER emptyFilter{};
        ReturnIfFailed(leakMessageQueue->PushRetrievalFilter(&emptyFilter));
        return S_OK;
    }

    // Returns E_FAIL if a device leak is detected.
    HRESULT ResourceAllocator::CheckForDeviceObjectLeaks() const {
        // Debug layer was never enabled.
        ComPtr<ID3D12DebugDevice> debugDevice;
        if (FAILED(mDevice.As(&debugDevice))) {
            return S_OK;
        }

        const D3D12_RLDO_FLAGS rldoFlags = D3D12_RLDO_DETAIL | D3D12_RLDO_IGNORE_INTERNAL;
        ReturnIfFailed(debugDevice->ReportLiveDeviceObjects(rldoFlags));

        ComPtr<ID3D12InfoQueue> leakMessageQueue;
        ReturnIfFailed(mDevice.As(&leakMessageQueue));

        // Count the reported live device objects messages that could be generated by GPGMM.
        // This is because the allowList filter cannot easily be made exclusive to these IDs.
        uint64_t totalLiveObjects = 0;
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
                    totalLiveObjects++;
                } break;
                default:
                    break;
            }
        }

        leakMessageQueue->PopRetrievalFilter();
        return (totalLiveObjects > 0u) ? E_FAIL : S_OK;
    }

    void ResourceAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        mInfo.UsedMemoryUsage -= allocation->GetSize();
        mInfo.UsedMemoryCount--;
        SafeRelease(allocation);
    }

}}  // namespace gpgmm::d3d12
