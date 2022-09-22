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

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/common/TraceEvent.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/utils/Math.h"
#include "tests/D3D12Test.h"

#include <gpgmm_d3d12.h>

#include <set>
#include <thread>

using namespace gpgmm::d3d12;

static constexpr uint64_t kBufferOf4MBAllocationSize = GPGMM_MB_TO_BYTES(4);
static constexpr uint64_t kReleaseAllMemory = std::numeric_limits<uint64_t>::max();

#define GPGMM_GET_VAR_NAME(x) (L#x)

#define EXPECT_SIZE_CACHE_HIT(allocator, statement)                \
    do {                                                           \
        ASSERT_NE(allocator, nullptr);                             \
        uint64_t countBefore = allocator->GetInfo().SizeCacheHits; \
        EXPECT_SUCCEEDED(statement);                               \
        uint64_t countAfter = allocator->GetInfo().SizeCacheHits;  \
        EXPECT_GT(countAfter, countBefore);                        \
    } while (0)

#define EXPECT_SIZE_CACHE_MISS(allocator, statement)                 \
    do {                                                             \
        ASSERT_NE(allocator, nullptr);                               \
        uint64_t countBefore = allocator->GetInfo().SizeCacheMisses; \
        EXPECT_SUCCEEDED(statement);                                 \
        uint64_t countAfter = allocator->GetInfo().SizeCacheMisses;  \
        EXPECT_GT(countAfter, countBefore);                          \
    } while (0)

class D3D12ResourceAllocatorTests : public D3D12TestBase, public ::testing::Test {
  protected:
    void SetUp() override {
        D3D12TestBase::SetUp();
    }

    void TearDown() override {
        D3D12TestBase::TearDown();
    }

    // Configures allocator for testing allocation in a controlled and predictable
    // fashion.
    ALLOCATOR_DESC CreateBasicAllocatorDesc() const {
        ALLOCATOR_DESC desc = D3D12TestBase::CreateBasicAllocatorDesc();

        // Pre-fetching is enabled by default. However for testing purposes, pre-fetching changes
        // expectations that check GPU memory usage and needs to be tested in isolation.
        desc.Flags |= ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH;

        // Make sure leak detection is always enabled.
        desc.Flags |= gpgmm::d3d12::ALLOCATOR_FLAG_NEVER_LEAK_MEMORY;

        return desc;
    }
};

TEST_F(D3D12ResourceAllocatorTests, CreateAllocator) {
    // Creating an invalid allocator should always fail.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        EXPECT_FAILED(ResourceAllocator::CreateAllocator({}, &resourceAllocator));
        EXPECT_EQ(resourceAllocator, nullptr);
    }

    // Creating an allocator without a device should always fail.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.Device = nullptr;

        ComPtr<ResourceAllocator> resourceAllocator;
        EXPECT_FAILED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
        EXPECT_EQ(resourceAllocator, nullptr);
    }

    // Creating an allocator with the wrong resource heap tier should always fail.
    {
        // Tier 3 doesn't exist in D3D12.
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.ResourceHeapTier =
            static_cast<D3D12_RESOURCE_HEAP_TIER>(D3D12_RESOURCE_HEAP_TIER_2 + 1);

        ComPtr<ResourceAllocator> resourceAllocator;
        EXPECT_FAILED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
        EXPECT_EQ(resourceAllocator, nullptr);
    }

    // Creating a NULL allocator should always succeed.
    EXPECT_SUCCEEDED(ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), nullptr));

    // Creating an allocator without an adapter should always fail.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.Adapter = nullptr;

        ComPtr<ResourceAllocator> resourceAllocator;
        EXPECT_FAILED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
        EXPECT_EQ(resourceAllocator, nullptr);
    }

    // Creating a new allocator using the defaults should always succeed.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        EXPECT_SUCCEEDED(
            ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
        EXPECT_NE(resourceAllocator, nullptr);
    }

    // Creating a new allocator with a preferred resource heap size larger then the max resource
    // heap size should always fail.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.PreferredResourceHeapSize = kBufferOf4MBAllocationSize;
        desc.MaxResourceHeapSize = kBufferOf4MBAllocationSize / 2;

        ComPtr<ResourceAllocator> resourceAllocator;
        EXPECT_FAILED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
        EXPECT_EQ(resourceAllocator, nullptr);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateAllocatorNoLeak) {
    GPGMM_TEST_MEMORY_LEAK_START();
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator);
    }
    GPGMM_TEST_MEMORY_LEAK_END();
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferNoLeak) {
    GPGMM_TEST_MEMORY_LEAK_START();
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator);
        for (auto& bufferAllocationExpectation : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            resourceAllocator->CreateResource(
                {},
                CreateBasicBufferDesc(bufferAllocationExpectation.size,
                                      bufferAllocationExpectation.alignment),
                D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation);
        }
    }
    GPGMM_TEST_MEMORY_LEAK_END();
}

// Exceeding the max resource heap size should always fail.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferAndTextureInSameHeap) {
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();

    // Heaps of only the same size can be reused between resource types.
    allocatorDesc.PreferredResourceHeapSize = kBufferOf4MBAllocationSize;

    // Adapter must support mixing of resource types in same heap.
    GPGMM_SKIP_TEST_IF(allocatorDesc.ResourceHeapTier < D3D12_RESOURCE_HEAP_TIER_2);

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));

    // Create memory for buffer in Heap A.
    {
        ComPtr<ResourceAllocation> bufferAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
            nullptr, &bufferAllocation));
    }

    EXPECT_EQ(resourceAllocator->GetInfo().FreeMemoryUsage, kBufferOf4MBAllocationSize);

    // Reuse memory for texture in Heap A.
    {
        ComPtr<ResourceAllocation> textureAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &textureAllocation));
    }

    EXPECT_EQ(resourceAllocator->GetInfo().FreeMemoryUsage, kBufferOf4MBAllocationSize);
}

// Exceeding the max resource heap size should always fail.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferAndTextureInSeperateHeap) {
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
    allocatorDesc.ResourceHeapTier = D3D12_RESOURCE_HEAP_TIER_1;

    // Heaps of only the same size can be reused between resource types.
    allocatorDesc.PreferredResourceHeapSize = kBufferOf4MBAllocationSize;

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));

    // Create memory for buffer in Heap A.
    {
        ComPtr<ResourceAllocation> bufferAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
            nullptr, &bufferAllocation));

        EXPECT_EQ(bufferAllocation->GetMemory()->GetSize(),
                  allocatorDesc.PreferredResourceHeapSize);
    }

    EXPECT_EQ(resourceAllocator->GetInfo().FreeMemoryUsage, kBufferOf4MBAllocationSize);

    // Reuse memory for texture in Heap A.
    {
        ComPtr<ResourceAllocation> textureAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &textureAllocation));

        EXPECT_EQ(textureAllocation->GetMemory()->GetSize(),
                  allocatorDesc.PreferredResourceHeapSize);
    }

    EXPECT_EQ(resourceAllocator->GetInfo().FreeMemoryUsage, kBufferOf4MBAllocationSize * 2);
}

// Exceeding the max resource heap size should always fail.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferOversized) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    constexpr uint64_t kOversizedBuffer = GPGMM_GB_TO_BYTES(32);
    ComPtr<ResourceAllocation> allocation;
    ASSERT_FAILED(resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kOversizedBuffer + 1),
                                                    D3D12_RESOURCE_STATE_COMMON, nullptr,
                                                    &allocation));
    ASSERT_EQ(allocation, nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferSubAllocated) {
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();

    // Ensure the underlying memory size is large enough so all buffer allocation can fit.
    allocatorDesc.PreferredResourceHeapSize = GPGMM_MB_TO_BYTES(64);

    // Ensure the allocation will never fall-back to use any method other than the one being tested.
    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.Flags = ALLOCATION_FLAG_NEVER_FALLBACK;

    // ALLOCATOR_ALGORITHM_BUDDY_SYSTEM
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_BUDDY_SYSTEM;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        for (auto& alloc : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                          allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                      alloc.succeeds);
        }
    }

    // ALLOCATOR_ALGORITHM_BUDDY_SYSTEM + ALLOCATOR_ALGORITHM_FIXED_POOL
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_BUDDY_SYSTEM;
        newAllocatorDesc.PoolAlgorithm = ALLOCATOR_ALGORITHM_FIXED_POOL;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        for (auto& alloc : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                          allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                      alloc.succeeds);
        }
    }

    // ALLOCATOR_ALGORITHM_BUDDY_SYSTEM + ALLOCATOR_ALGORITHM_SEGMENTED_POOL
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_BUDDY_SYSTEM;
        newAllocatorDesc.PoolAlgorithm = ALLOCATOR_ALGORITHM_SEGMENTED_POOL;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        for (auto& alloc : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                          allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                      alloc.succeeds);
        }
    }

    // ALLOCATOR_ALGORITHM_SLAB
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_SLAB;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        for (auto& alloc : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                          allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                      alloc.succeeds);
        }
    }

    // ALLOCATOR_ALGORITHM_SLAB + ALLOCATOR_ALGORITHM_FIXED_POOL
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_SLAB;
        newAllocatorDesc.PoolAlgorithm = ALLOCATOR_ALGORITHM_FIXED_POOL;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        for (auto& alloc : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                          allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                      alloc.succeeds);
        }
    }

    // ALLOCATOR_ALGORITHM_SLAB + ALLOCATOR_ALGORITHM_SEGMENTED_POOL
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_SLAB;
        newAllocatorDesc.PoolAlgorithm = ALLOCATOR_ALGORITHM_SEGMENTED_POOL;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        for (auto& alloc : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                          allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                      alloc.succeeds);
        }
    }

    // No sub-allocation algorithm.
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.Flags |= ALLOCATOR_FLAG_ALWAYS_COMMITED;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        for (auto& alloc : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                          allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                      alloc.succeeds);
        }
    }

    // ALLOCATOR_ALGORITHM_DEDICATED
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_DEDICATED;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        for (auto& alloc : GenerateBufferAllocations()) {
            ComPtr<ResourceAllocation> allocation;
            EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                          allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                      alloc.succeeds);
        }
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferWithPreferredHeapSize) {
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();

    // ALLOCATOR_ALGORITHM_SLAB
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_SLAB;
        newAllocatorDesc.PreferredResourceHeapSize = GPGMM_MB_TO_BYTES(12);

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        // Slab allocator requires heaps to be in aligned in powers-of-two sizes.
        EXPECT_EQ(allocation->GetMemory()->GetSize(), GPGMM_MB_TO_BYTES(16));
    }

    // ALLOCATOR_ALGORITHM_BUDDY_SYSTEM
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_BUDDY_SYSTEM;
        newAllocatorDesc.PreferredResourceHeapSize = GPGMM_MB_TO_BYTES(12);

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        // Buddy allocator requires heaps to be in aligned in powers-of-two sizes.
        EXPECT_EQ(allocation->GetMemory()->GetSize(), GPGMM_MB_TO_BYTES(16));
    }

    // ALLOCATOR_ALGORITHM_DEDICATED
    {
        ALLOCATOR_DESC newAllocatorDesc = allocatorDesc;
        newAllocatorDesc.SubAllocationAlgorithm = ALLOCATOR_ALGORITHM_DEDICATED;
        newAllocatorDesc.PreferredResourceHeapSize = GPGMM_MB_TO_BYTES(12);

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(newAllocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        // Dedicated allocator ignores the preferred resource heap size and allocates exactly what
        // is needed.
        EXPECT_EQ(allocation->GetMemory()->GetSize(), kBufferOf4MBAllocationSize);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferManyDeallocateAtEnd) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    std::set<ComPtr<ResourceAllocation>> allocs = {};
    for (auto& alloc : GenerateBufferAllocations()) {
        ComPtr<ResourceAllocation> allocation;
        EXPECT_EQ(SUCCEEDED(resourceAllocator->CreateResource(
                      allocationDesc, CreateBasicBufferDesc(alloc.size, alloc.alignment),
                      D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation)),
                  alloc.succeeds);

        if (allocation == nullptr) {
            continue;
        }

        ASSERT_NE(allocation, nullptr);
        EXPECT_TRUE(allocs.insert(allocation).second);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateBuffer) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // Creating a resource without allocation should still succeed.
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
            nullptr, nullptr));
    }

    // Using the min resource heap size should always succeed.
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
            nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        ASSERT_NE(allocation->GetResource(), nullptr);
    }

    // Mapping the entire buffer should always succeed.
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        ASSERT_NE(allocation->GetResource(), nullptr);

        ASSERT_SUCCEEDED(allocation->Map());
    }

    // Resource per heap type should always succeed if the heap type is allowed.
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, nullptr));
    }
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_READBACK;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_COPY_DEST, nullptr, nullptr));
    }
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
            nullptr, nullptr));
    }
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_CUSTOM;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
            nullptr, nullptr));
    }

    // Creating a zero sized buffer is not allowed.
    {
        ASSERT_FAILED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(0), D3D12_RESOURCE_STATE_COMMON, nullptr, nullptr));
    }

    // Creating a buffer with a custom heap flag should always succeed.
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;
        allocationDesc.ExtraRequiredHeapFlags = D3D12_HEAP_FLAG_SHARED;

        // D3D12_HEAP_FLAG_SHARED is incompatible CPU accessible heaps.
        allocationDesc.Flags = ALLOCATION_FLAG_ALWAYS_ATTRIBUTE_HEAPS;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
            nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);

        ComPtr<Heap> heap = allocation->GetMemory();
        ASSERT_NE(heap, nullptr);

        ComPtr<ID3D12Heap> d3dHeap;
        ASSERT_FAILED(heap.As(&d3dHeap));
    }

    // Creating a buffer with required but invalid heap flag should always fail.
    {
        ALLOCATION_DESC allocationDescWithInvalidHeapFlags = {};
        allocationDescWithInvalidHeapFlags.HeapType = D3D12_HEAP_TYPE_DEFAULT;
        allocationDescWithInvalidHeapFlags.ExtraRequiredHeapFlags =
            static_cast<D3D12_HEAP_FLAGS>(0xFF);

        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(resourceAllocator->CreateResource(
            allocationDescWithInvalidHeapFlags, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
    }

    // Creating a buffer with a name should be always specified.
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;
        allocationDesc.DebugName = L"Buffer";

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
            nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQUAL_WSTR(allocation->GetDebugName(), allocationDesc.DebugName);
    }

    // Creating a buffer without a heap type should be inferred based on the resource state.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
            &allocation));
        ASSERT_NE(allocation, nullptr);
    }
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_GENERIC_READ,
            nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
    }
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_UNORDERED_ACCESS,
            nullptr, &allocation));
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferLeaked) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ComPtr<ResourceAllocation> allocation;
    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

    allocation.Detach();  // leaked!
}

// Verifies there are no attribution of heaps when UMA + no read-back.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferUMA) {
    GPGMM_SKIP_TEST_IF(!mCaps->IsAdapterUMA());

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                          D3D12_RESOURCE_STATE_COMMON, nullptr, nullptr));

    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                          D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, nullptr));

    EXPECT_EQ(resourceAllocator->GetInfo().FreeMemoryUsage, kBufferOf4MBAllocationSize);

    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                          D3D12_RESOURCE_STATE_COPY_DEST, nullptr, nullptr));

    EXPECT_EQ(resourceAllocator->GetInfo().FreeMemoryUsage, kBufferOf4MBAllocationSize);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_READBACK;

    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource(allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                          D3D12_RESOURCE_STATE_COPY_DEST, nullptr, nullptr));

    EXPECT_EQ(resourceAllocator->GetInfo().FreeMemoryUsage, kBufferOf4MBAllocationSize * 2);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferDisableCustomHeaps) {
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
    allocatorDesc.Flags |= ALLOCATOR_FLAG_DISABLE_CUSTOM_HEAPS;

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));

    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
            &allocation));

        D3D12_HEAP_PROPERTIES heapProperties = {};
        ASSERT_SUCCEEDED(allocation->GetResource()->GetHeapProperties(&heapProperties, nullptr));
        EXPECT_NE(heapProperties.Type, D3D12_HEAP_TYPE_CUSTOM);
    }
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_CUSTOM;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_COPY_DEST, nullptr, nullptr));
    }

    // Abandonment of heap type attribution is disallowed when custom heaps are disabled.
    resourceAllocator->ReleaseMemory(kReleaseAllMemory);
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.Flags = ALLOCATION_FLAG_ALWAYS_ATTRIBUTE_HEAPS;

        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_COPY_DEST, nullptr, nullptr));

        allocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, nullptr));

        EXPECT_EQ(resourceAllocator->GetInfo().FreeMemoryUsage, kBufferOf4MBAllocationSize * 2);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateSmallTexture) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // DXGI_FORMAT_R8G8B8A8_UNORM
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_TRUE(
            gpgmm::IsAligned(allocation->GetSize(),
                             static_cast<uint32_t>(D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT)));
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateMultisampledTexture) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // DXGI_FORMAT_R8G8B8A8_UNORM
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1, 4),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_TRUE(gpgmm::IsAligned(
            allocation->GetSize(),
            static_cast<uint32_t>(D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT)));

        EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryCount, 1u);
    }

    EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryCount, 0u);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferImported) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // Importing a non-existent buffer should always fail.
    ComPtr<ResourceAllocation> externalAllocation;
    ASSERT_FAILED(resourceAllocator->CreateResource(nullptr, &externalAllocation));
    ASSERT_EQ(externalAllocation, nullptr);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    // Importing a buffer should always succeed.
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize), D3D12_RESOURCE_STATE_COMMON,
        nullptr, &externalAllocation));
    ASSERT_NE(externalAllocation, nullptr);

    ComPtr<ResourceAllocation> internalAllocation;
    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource(externalAllocation->GetResource(), &internalAllocation));
    ASSERT_NE(internalAllocation, nullptr);

    // Underlying resource must stay the same.
    ASSERT_EQ(internalAllocation->GetResource(), externalAllocation->GetResource());
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferInvalid) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // Garbage buffer descriptor should always fail.
    D3D12_RESOURCE_DESC badBufferDesc = CreateBasicBufferDesc(kBufferOf4MBAllocationSize);
    badBufferDesc.Flags = static_cast<D3D12_RESOURCE_FLAGS>(0xFF);

    ComPtr<ResourceAllocation> allocation;
    ASSERT_FAILED(resourceAllocator->CreateResource({}, badBufferDesc, D3D12_RESOURCE_STATE_COMMON,
                                                    nullptr, &allocation));
    ASSERT_EQ(allocation, nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferAlwaysCommitted) {
    ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
    desc.Flags = ALLOCATOR_FLAG_ALWAYS_COMMITED;

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<ResourceAllocation> allocation;
    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource(allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetSize(), kBufferOf4MBAllocationSize);

    // Commmitted resources cannot be backed by a D3D12 heap.
    ComPtr<Heap> resourceHeap = allocation->GetMemory();
    ASSERT_NE(resourceHeap, nullptr);

    ComPtr<ID3D12Heap> heap;
    ASSERT_FAILED(resourceHeap.As(&heap));

    // Commited resources must use all the memory allocated.
    EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryUsage, kBufferOf4MBAllocationSize);
    EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockUsage,
              resourceAllocator->GetInfo().UsedMemoryUsage);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferNeverAllocate) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // Check we can't reuse memory if CreateResource was never called previously.
    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.Flags = ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<ResourceAllocation> allocation;
    ASSERT_FAILED(resourceAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize + 1), D3D12_RESOURCE_STATE_COMMON,
        nullptr, &allocation));
    ASSERT_EQ(allocation, nullptr);

    constexpr uint64_t bufferSize = kBufferOf4MBAllocationSize / 8;

    allocationDesc.Flags = ALLOCATION_FLAG_NONE;
    ComPtr<ResourceAllocation> allocationA;
    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource(allocationDesc, CreateBasicBufferDesc(bufferSize),
                                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocationA));
    ASSERT_NE(allocationA, nullptr);

    // Allow the memory from |allocationA| to be recycled.
    allocationA.Reset();

    // Re-check that the same resource heap is used once CreateResource gets called.
    allocationDesc.Flags = ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
    ComPtr<ResourceAllocation> allocationB;
    ASSERT_SUCCEEDED(
        resourceAllocator->CreateResource(allocationDesc, CreateBasicBufferDesc(bufferSize),
                                          D3D12_RESOURCE_STATE_COMMON, nullptr, &allocationB));
    ASSERT_NE(allocationB, nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferWithin) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC baseAllocationDesc = {};
    baseAllocationDesc.Flags = ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE;

    {
        ALLOCATION_DESC smallBufferDesc = baseAllocationDesc;
        smallBufferDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            smallBufferDesc, CreateBasicBufferDesc(4u, 1), D3D12_RESOURCE_STATE_GENERIC_READ,
            nullptr, &smallBuffer));

        EXPECT_EQ(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
        EXPECT_EQ(smallBuffer->GetSize(), 4u);
        EXPECT_EQ(smallBuffer->GetOffsetFromResource(), 0u);
        EXPECT_EQ(smallBuffer->GetAlignment(), 4u);  // Must re-align.

        EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryCount, 1u);
        EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockUsage, smallBuffer->GetSize());
    }
    {
        ALLOCATION_DESC smallBufferWithinDesc = baseAllocationDesc;
        smallBufferWithinDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            smallBufferWithinDesc, CreateBasicBufferDesc(4u, 16), D3D12_RESOURCE_STATE_GENERIC_READ,
            nullptr, &smallBuffer));

        EXPECT_EQ(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
        EXPECT_EQ(smallBuffer->GetSize(), 16u);
        EXPECT_EQ(smallBuffer->GetOffsetFromResource(), 0u);
        EXPECT_EQ(smallBuffer->GetAlignment(), 16u);

        EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryCount, 1u);
        EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockUsage, smallBuffer->GetSize());
    }
    {
        ALLOCATION_DESC smallBufferWithinDesc = baseAllocationDesc;
        smallBufferWithinDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            smallBufferWithinDesc, CreateBasicBufferDesc(4u), D3D12_RESOURCE_STATE_GENERIC_READ,
            nullptr, &smallBuffer));

        EXPECT_EQ(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
        EXPECT_EQ(smallBuffer->GetSize(), 256u);
        EXPECT_EQ(smallBuffer->GetOffsetFromResource(), 0u);
        EXPECT_EQ(smallBuffer->GetAlignment(), 256u);  // Re-align

        EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockCount, 1u);
        EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryCount, 1u);
        EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockUsage, smallBuffer->GetSize());
    }
    {
        ALLOCATION_DESC smallBufferWithinDesc = baseAllocationDesc;
        smallBufferWithinDesc.HeapType = D3D12_HEAP_TYPE_READBACK;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            smallBufferWithinDesc, CreateBasicBufferDesc(4u), D3D12_RESOURCE_STATE_COPY_DEST,
            nullptr, &smallBuffer));

        EXPECT_EQ(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
        EXPECT_EQ(smallBuffer->GetSize(), 4u);
        EXPECT_EQ(smallBuffer->GetOffsetFromResource(), 0u);
        EXPECT_EQ(smallBuffer->GetAlignment(), 4u);
    }
    {
        ALLOCATION_DESC smallBufferWithinDesc = baseAllocationDesc;
        smallBufferWithinDesc.HeapType = D3D12_HEAP_TYPE_READBACK;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            smallBufferWithinDesc, CreateBasicBufferDesc(3u), D3D12_RESOURCE_STATE_COPY_DEST,
            nullptr, &smallBuffer));

        EXPECT_EQ(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
        EXPECT_EQ(smallBuffer->GetSize(), 4u);
        EXPECT_EQ(smallBuffer->GetOffsetFromResource(), 0u);
        EXPECT_EQ(smallBuffer->GetAlignment(), 4u);  // Re-align
    }

    // Default heap using a required resource state of another compatible heap type is not allowed.
    {
        ALLOCATION_DESC invalidSmallBufferWithinDesc = baseAllocationDesc;
        invalidSmallBufferWithinDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            invalidSmallBufferWithinDesc, CreateBasicBufferDesc(3u), D3D12_RESOURCE_STATE_COPY_DEST,
            nullptr, &smallBuffer));
        EXPECT_NE(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    }

    // Non-compatible heap type is not allowed reguardless of resource state specified.
    {
        ALLOCATION_DESC invalidSmallBufferWithinDesc = baseAllocationDesc;
        invalidSmallBufferWithinDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            invalidSmallBufferWithinDesc, CreateBasicBufferDesc(3u), D3D12_RESOURCE_STATE_COMMON,
            nullptr, &smallBuffer));
        EXPECT_NE(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    }

    // Custom heaps should use a heap type inferred by the resource state required.
    {
        ALLOCATION_DESC smallBufferWithinDesc = baseAllocationDesc;
        smallBufferWithinDesc.HeapType = D3D12_HEAP_TYPE_CUSTOM;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            smallBufferWithinDesc, CreateBasicBufferDesc(3u), D3D12_RESOURCE_STATE_COPY_DEST,
            nullptr, &smallBuffer));
        EXPECT_EQ(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    }

    // Unspecified heap type should use the heap type inferred by the resource state
    // required.
    {
        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            baseAllocationDesc, CreateBasicBufferDesc(3u), D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
            &smallBuffer));
        EXPECT_EQ(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    }
    {
        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource(baseAllocationDesc, CreateBasicBufferDesc(3u),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &smallBuffer));
        EXPECT_NE(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    }

    // Resource flags are not allowed.
    {
        D3D12_RESOURCE_DESC resourceDescWithFlags = CreateBasicBufferDesc(3u);
        resourceDescWithFlags.Flags = D3D12_RESOURCE_FLAG_DENY_SHADER_RESOURCE;

        ComPtr<ResourceAllocation> smallBuffer;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            baseAllocationDesc, resourceDescWithFlags, D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
            &smallBuffer));
        EXPECT_NE(smallBuffer->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferWithinMany) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.Flags = ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE;
    allocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

    const D3D12_RESOURCE_DESC& smallBufferDesc = CreateBasicBufferDesc(4u, 1);

    // Create two small buffers that will be byte-aligned.
    ComPtr<ResourceAllocation> smallBufferA;
    allocationDesc.DebugName = GPGMM_GET_VAR_NAME(smallBufferA);

    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(allocationDesc, smallBufferDesc,
                                                       D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                                       &smallBufferA));
    ASSERT_NE(smallBufferA, nullptr);
    EXPECT_EQ(smallBufferA->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    EXPECT_EQ(smallBufferA->GetSize(), smallBufferDesc.Width);

    ComPtr<ResourceAllocation> smallBufferB;
    allocationDesc.DebugName = GPGMM_GET_VAR_NAME(smallBufferB);

    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(allocationDesc, smallBufferDesc,
                                                       D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                                       &smallBufferB));
    ASSERT_NE(smallBufferB, nullptr);
    EXPECT_EQ(smallBufferB->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    EXPECT_EQ(smallBufferB->GetSize(), smallBufferDesc.Width);

    ComPtr<ResourceAllocation> smallBufferC;
    allocationDesc.DebugName = GPGMM_GET_VAR_NAME(smallBufferC);

    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(allocationDesc, smallBufferDesc,
                                                       D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
                                                       &smallBufferC));
    ASSERT_NE(smallBufferC, nullptr);
    EXPECT_EQ(smallBufferC->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    EXPECT_EQ(smallBufferC->GetSize(), smallBufferDesc.Width);

    EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockCount, 3u);
    EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryCount, 1u);

    // Should be allocated in sequence, back-to-back.
    EXPECT_EQ(smallBufferA->GetOffsetFromResource() + smallBufferDesc.Width,
              smallBufferB->GetOffsetFromResource());

    EXPECT_EQ(smallBufferB->GetOffsetFromResource() + smallBufferDesc.Width,
              smallBufferC->GetOffsetFromResource());

    EXPECT_EQ(smallBufferA->GetGPUVirtualAddress() + smallBufferDesc.Width,
              smallBufferB->GetGPUVirtualAddress());

    EXPECT_EQ(smallBufferB->GetGPUVirtualAddress() + smallBufferDesc.Width,
              smallBufferC->GetGPUVirtualAddress());

    // Should share the same resource.
    EXPECT_EQ(smallBufferA->GetResource(), smallBufferB->GetResource());
    EXPECT_EQ(smallBufferB->GetResource(), smallBufferC->GetResource());

    // Mapping within must use the entire resource.
    ASSERT_FAILED(smallBufferA->Map(/*subresource*/ 1));
    ASSERT_FAILED(smallBufferB->Map(/*subresource*/ 1));
    ASSERT_FAILED(smallBufferC->Map(/*subresource*/ 1));

    // Fill small buffer C with value 0xCC.
    std::vector<uint8_t> dataCC(static_cast<const size_t>(smallBufferC->GetSize()), 0xCC);
    void* mappedBufferC = nullptr;
    ASSERT_SUCCEEDED(smallBufferC->Map(0, nullptr, &mappedBufferC));
    memcpy(mappedBufferC, dataCC.data(), dataCC.size());

    // Fill small buffer A with value 0xAA.
    std::vector<uint8_t> dataAA(static_cast<const size_t>(smallBufferA->GetSize()), 0xAA);
    void* mappedBufferA = nullptr;
    ASSERT_SUCCEEDED(smallBufferA->Map(0, nullptr, &mappedBufferA));
    memcpy(mappedBufferA, dataAA.data(), dataAA.size());

    // Fill small buffer B with value 0xBB.
    std::vector<uint8_t> dataBB(static_cast<const size_t>(smallBufferB->GetSize()), 0xBB);
    void* mappedBufferB = nullptr;
    ASSERT_SUCCEEDED(smallBufferB->Map(0, nullptr, &mappedBufferB));
    memcpy(mappedBufferB, dataBB.data(), dataBB.size());

    EXPECT_NE(mappedBufferA, mappedBufferB);
    EXPECT_NE(mappedBufferB, mappedBufferC);

    // Map the entire resource and check values, in-order.
    void* mappedBuffer = nullptr;
    ASSERT_SUCCEEDED(smallBufferB->GetResource()->Map(0, nullptr, &mappedBuffer));

    const uint8_t* mappedByte = static_cast<uint8_t*>(mappedBuffer);
    for (uint32_t i = 0; i < smallBufferA->GetSize(); i++, mappedByte++) {
        EXPECT_EQ(*mappedByte, 0xAA);
    }

    for (uint32_t i = 0; i < smallBufferB->GetSize(); i++, mappedByte++) {
        EXPECT_EQ(*mappedByte, 0xBB);
    }

    for (uint32_t i = 0; i < smallBufferC->GetSize(); i++, mappedByte++) {
        EXPECT_EQ(*mappedByte, 0xCC);
    }

    // Deallocate in reverse order (for good measure).
    smallBufferA = nullptr;
    smallBufferB = nullptr;
    smallBufferC = nullptr;

    EXPECT_EQ(resourceAllocator->GetInfo().UsedBlockCount, 0u);
    EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryCount, 0u);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferNeverSubAllocated) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    constexpr uint64_t bufferSize = kBufferOf4MBAllocationSize / 2;

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;
    allocationDesc.Flags = ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;

    ComPtr<ResourceAllocation> subAllocation;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(bufferSize), D3D12_RESOURCE_STATE_GENERIC_READ,
        nullptr, &subAllocation));
    ASSERT_NE(subAllocation, nullptr);
    EXPECT_NE(subAllocation->GetResource(), nullptr);
    EXPECT_NE(subAllocation->GetMethod(), gpgmm::AllocationMethod::kSubAllocated);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferNeverPooled) {
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
    allocatorDesc.Flags |= ALLOCATOR_FLAG_ALWAYS_ON_DEMAND;

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC baseAllocationDesc = {};
    baseAllocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

    constexpr uint64_t bufferSize = kBufferOf4MBAllocationSize;

    // Create the first buffer of size A without recyling its memory.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            baseAllocationDesc, CreateBasicBufferDesc(bufferSize * 2),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_NE(allocation->GetResource(), nullptr);
    }

    // Check the first buffer of size A cannot be from recycled memory.
    {
        ALLOCATION_DESC allocationDesc = baseAllocationDesc;
        allocationDesc.Flags = ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(bufferSize * 2),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
    }

    // Create another buffer of size B which cannot use recycled memory of size A.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            baseAllocationDesc, CreateBasicBufferDesc(bufferSize * 3),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_NE(allocation->GetResource(), nullptr);
    }

    // Check the second buffer of size B cannot be from recycled memory.
    {
        ALLOCATION_DESC allocationDesc = baseAllocationDesc;
        allocationDesc.Flags = ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(bufferSize * 3),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferPooled) {
    constexpr uint64_t bufferSize = kBufferOf4MBAllocationSize;

    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();

    ComPtr<ResourceAllocator> poolAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &poolAllocator));
    ASSERT_NE(poolAllocator, nullptr);

    // Only standalone allocations can be pool-allocated.
    ALLOCATION_DESC standaloneAllocationDesc = {};
    standaloneAllocationDesc.Flags = ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;
    standaloneAllocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

    // Create buffer of size A with it's own resource heap that will be returned to the pool.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(poolAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(bufferSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_NE(allocation->GetResource(), nullptr);
        EXPECT_EQ(allocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }

    // Create buffer of size B with it's own resource heap that will be returned to the pool.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(poolAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(bufferSize / 2),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_NE(allocation->GetResource(), nullptr);
        EXPECT_EQ(allocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }

    // Create buffer of size A again with it's own resource heap from the pool.
    {
        ALLOCATION_DESC reusePoolOnlyDesc = standaloneAllocationDesc;
        reusePoolOnlyDesc.Flags =
            standaloneAllocationDesc.Flags | ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            poolAllocator->CreateResource(reusePoolOnlyDesc, CreateBasicBufferDesc(bufferSize),
                                          D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_NE(allocation->GetResource(), nullptr);
        EXPECT_EQ(allocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }

    // Create buffer of size B again with it's own resource heap from the pool.
    {
        ALLOCATION_DESC reusePoolOnlyDesc = standaloneAllocationDesc;
        reusePoolOnlyDesc.Flags =
            standaloneAllocationDesc.Flags | ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            poolAllocator->CreateResource(reusePoolOnlyDesc, CreateBasicBufferDesc(bufferSize / 2),
                                          D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_NE(allocation->GetResource(), nullptr);
        EXPECT_EQ(allocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }

    EXPECT_EQ(poolAllocator->GetInfo().FreeMemoryUsage, bufferSize + bufferSize / 2);

    EXPECT_EQ(poolAllocator->ReleaseMemory(kReleaseAllMemory), bufferSize + bufferSize / 2);

    EXPECT_EQ(poolAllocator->GetInfo().FreeMemoryUsage, 0u);

    // Create buffer of size A again with it's own resource heap from the empty pool.
    {
        ALLOCATION_DESC reusePoolOnlyDesc = standaloneAllocationDesc;
        reusePoolOnlyDesc.Flags =
            standaloneAllocationDesc.Flags | ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(
            poolAllocator->CreateResource(reusePoolOnlyDesc, CreateBasicBufferDesc(bufferSize),
                                          D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
    }

    // Create buffer of size A again with it's own resource heap from the empty pool.
    {
        ALLOCATION_DESC reusePoolOnlyDesc = standaloneAllocationDesc;
        reusePoolOnlyDesc.Flags =
            standaloneAllocationDesc.Flags | ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(
            poolAllocator->CreateResource(reusePoolOnlyDesc, CreateBasicBufferDesc(bufferSize / 2),
                                          D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
    }

    // Creating a new allocator using a misaligned max resource size for pooling should succeed.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(1024),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }

    EXPECT_EQ(poolAllocator->GetInfo().FreeMemoryUsage, 0u);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferGetInfo) {
    // Calculate info for a single standalone allocation.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(
            ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ALLOCATION_DESC standaloneAllocationDesc = {};
        standaloneAllocationDesc.Flags = ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;
        standaloneAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ResourceAllocation> firstAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &firstAllocation));
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);

        RESOURCE_ALLOCATOR_INFO info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 1u);
        EXPECT_EQ(info.UsedMemoryUsage, kBufferOf4MBAllocationSize);
    }

    // Calculate info for two pooled standalone allocations.
    {
        ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ALLOCATION_DESC standaloneAllocationDesc = {};
        standaloneAllocationDesc.Flags = ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;
        standaloneAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ResourceAllocation> firstAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &firstAllocation));
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);

        RESOURCE_ALLOCATOR_INFO info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 1u);
        EXPECT_EQ(info.UsedMemoryUsage, kBufferOf4MBAllocationSize);

        ComPtr<ResourceAllocation> secondAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &secondAllocation));
        ASSERT_NE(secondAllocation, nullptr);
        EXPECT_EQ(secondAllocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);

        info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 2u);
        EXPECT_EQ(info.UsedMemoryUsage, kBufferOf4MBAllocationSize * 2);
    }

    // Calculate info for two sub-allocations.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(
            ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ALLOCATION_DESC subAllocationDesc = {};
        subAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        constexpr uint64_t kBufferSize = kBufferOf4MBAllocationSize / 8;
        ComPtr<ResourceAllocation> firstAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            subAllocationDesc, CreateBasicBufferDesc(kBufferSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &firstAllocation));
        ASSERT_NE(firstAllocation, nullptr);

        // Depending on the device, sub-allocation could fail. Since this test relies on a
        // sub-allocator's info counts, it must be skipped.
        // TODO: Consider testing counts by allocator type.
        GPGMM_SKIP_TEST_IF(firstAllocation->GetMethod() != gpgmm::AllocationMethod::kSubAllocated);

        RESOURCE_ALLOCATOR_INFO info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 1u);
        EXPECT_GE(info.UsedMemoryUsage, info.UsedBlockUsage);
        EXPECT_EQ(info.UsedBlockCount, 1u);
        EXPECT_GE(info.UsedBlockUsage, kBufferSize);

        ComPtr<ResourceAllocation> secondAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            subAllocationDesc, CreateBasicBufferDesc(kBufferSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &secondAllocation));
        ASSERT_NE(secondAllocation, nullptr);
        EXPECT_EQ(secondAllocation->GetMethod(), gpgmm::AllocationMethod::kSubAllocated);

        info = resourceAllocator->GetInfo();
        EXPECT_GE(info.UsedMemoryCount, 1u);
        EXPECT_GE(info.UsedMemoryUsage, info.UsedBlockUsage);
        EXPECT_EQ(info.UsedBlockCount, 2u);
        EXPECT_GE(info.UsedBlockUsage, kBufferSize * 2);
    }

    // Calculate info for two sub-allocations within the same resource.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(
            ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ALLOCATION_DESC allocationWithinDesc = {};
        allocationWithinDesc.Flags = ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE;
        allocationWithinDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        constexpr uint32_t kBufferSize = 4u;  // Must less than 64KB

        ComPtr<ResourceAllocation> firstAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationWithinDesc, CreateBasicBufferDesc(kBufferSize, 1),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &firstAllocation));
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);

        RESOURCE_ALLOCATOR_INFO info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 1u);
        EXPECT_EQ(info.UsedMemoryUsage, 64u * 1024u);
        EXPECT_EQ(info.UsedBlockCount, 1u);
        EXPECT_EQ(info.UsedBlockUsage, kBufferSize);

        ComPtr<ResourceAllocation> secondAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationWithinDesc, CreateBasicBufferDesc(kBufferSize, 1),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &secondAllocation));
        ASSERT_NE(secondAllocation, nullptr);
        EXPECT_EQ(secondAllocation->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);

        info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 1u);
        EXPECT_EQ(info.UsedMemoryUsage, 64u * 1024u);
        EXPECT_EQ(info.UsedBlockCount, 2u);
        EXPECT_EQ(info.UsedBlockUsage, kBufferSize * 2);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateTexturePooled) {
    ComPtr<ResourceAllocator> poolAllocator;
    {
        ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &poolAllocator));
        ASSERT_NE(poolAllocator, nullptr);
    }

    // Only standalone allocations can be pool-allocated.
    ALLOCATION_DESC standaloneAllocationDesc = {};
    standaloneAllocationDesc.Flags = ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;
    standaloneAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    // Create a small texture of size A with it's own resource heap that will be returned to the
    // pool.
    {
        ComPtr<ResourceAllocation> firstAllocation;
        ASSERT_SUCCEEDED(poolAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &firstAllocation));
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }

    ALLOCATION_DESC reusePoolOnlyDesc = standaloneAllocationDesc;
    reusePoolOnlyDesc.Flags =
        standaloneAllocationDesc.Flags | ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;

    // Check the first small texture of size A was pool-allocated by creating it again.
    {
        ComPtr<ResourceAllocation> secondAllocation;
        ASSERT_SUCCEEDED(poolAllocator->CreateResource(
            reusePoolOnlyDesc, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &secondAllocation));
        ASSERT_NE(secondAllocation, nullptr);
        EXPECT_EQ(secondAllocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }
}

// Verify a 1 byte buffer will be defragmented by creating a heaps large enough to stay under the
// fragmentation limit.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferWithLimitedFragmentation) {
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
    allocatorDesc.MemoryFragmentationLimit = 0.0265;  // or 2.65%

    ALLOCATION_DESC baseAllocationDesc = {};
    baseAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    // A 1 byte buffer causes 64KB - 1 worth of resource fragmentation.
    // This means a resource heap equal to 64 pages is required to be created, since 64KB - 1B <
    // (64KB * 64)* 2.65%.

    // By default, buffer should be sub-allocated.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource(baseAllocationDesc, CreateBasicBufferDesc(1),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        EXPECT_EQ(allocation->GetMemory()->GetSize(), 64 * 65536u);
    }

    // Force standalone buffer creation.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ALLOCATION_DESC standaloneAllocationDesc = baseAllocationDesc;
        standaloneAllocationDesc.Flags |= ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource(standaloneAllocationDesc, CreateBasicBufferDesc(1),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        EXPECT_EQ(allocation->GetMemory()->GetSize(), 65536u);
    }

    // Repeat standalone buffer creation, but using a committed resource.
    {
        allocatorDesc.Flags |= ALLOCATOR_FLAG_ALWAYS_COMMITED;

        ComPtr<ResourceAllocator> commitedAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &commitedAllocator));
        ASSERT_NE(commitedAllocator, nullptr);

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            commitedAllocator->CreateResource(baseAllocationDesc, CreateBasicBufferDesc(1),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        EXPECT_EQ(allocation->GetMemory()->GetSize(), 65536u);
    }
}

// Creates a bunch of small buffers using the smallest size allowed with pre-fetching enabled.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferManyPrefetch) {
    // Prefetching is explicitly disabled but otherwise allowed, re-enable it by clearing the
    // disable flag.
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
    allocatorDesc.Flags ^= ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH;

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    constexpr uint64_t kNumOfBuffers = 1000u;

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;
    allocationDesc.Flags = ALLOCATION_FLAG_ALWAYS_PREFETCH_MEMORY;

    constexpr uint32_t kMinBufferSize = GPGMM_KB_TO_BYTES(64);

    std::set<ComPtr<ResourceAllocation>> allocs = {};
    for (uint64_t i = 0; i < kNumOfBuffers; i++) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource(allocationDesc, CreateBasicBufferDesc(kMinBufferSize),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        allocs.insert(allocation);
    }

    allocs.clear();
}

// Creates a bunch of buffers concurrently.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferManyThreaded) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    constexpr uint32_t kThreadCount = 64u;
    std::vector<std::thread> threads(kThreadCount);
    for (size_t threadIdx = 0; threadIdx < threads.size(); threadIdx++) {
        threads[threadIdx] = std::thread([&]() {
            ComPtr<ResourceAllocation> allocation;
            ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
                allocationDesc, CreateBasicBufferDesc(kBufferOf4MBAllocationSize),
                D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
            ASSERT_NE(allocation, nullptr);
        });
    }

    for (std::thread& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryUsage, 0u);
}

// Creates a bunch of buffers concurrently.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferWithinManyThreaded) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.Flags = ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE;
    allocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

    constexpr uint32_t kSmallBufferSize = 256u;

    constexpr uint32_t kThreadCount = 64u;
    std::vector<std::thread> threads(kThreadCount);
    for (size_t threadIdx = 0; threadIdx < threads.size(); threadIdx++) {
        threads[threadIdx] = std::thread([&]() {
            ComPtr<ResourceAllocation> allocation;
            ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
                allocationDesc, CreateBasicBufferDesc(kSmallBufferSize),
                D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
            ASSERT_NE(allocation, nullptr);
            EXPECT_EQ(allocation->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
        });
    }

    for (std::thread& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryUsage, 0u);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferCacheSize) {
    // Since we cannot determine which resource sizes will be cached upon CreateAllocator, skip the
    // test.
    GPGMM_SKIP_TEST_IF(IsSizeCacheEnabled());

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // First request is always a cache miss.
    ALLOCATION_DESC baseAllocationDesc = {};
    baseAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;
    baseAllocationDesc.Flags |= ALLOCATION_FLAG_ALWAYS_CACHE_SIZE;

    {
        ComPtr<ResourceAllocation> allocation;

        ALLOCATION_DESC smallResourceAllocDesc = baseAllocationDesc;
        smallResourceAllocDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;
        smallResourceAllocDesc.Flags |= ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE;

        EXPECT_SIZE_CACHE_MISS(resourceAllocator,
                               resourceAllocator->CreateResource(
                                   smallResourceAllocDesc,
                                   CreateBasicBufferDesc(static_cast<uint64_t>(
                                       D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT)),
                                   D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(),
                  static_cast<uint64_t>(D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT));
    }
    {
        ComPtr<ResourceAllocation> allocation;
        EXPECT_SIZE_CACHE_MISS(
            resourceAllocator,
            resourceAllocator->CreateResource(
                baseAllocationDesc,
                CreateBasicBufferDesc(D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT),
                D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(),
                  static_cast<uint64_t>(D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT));
    }
    {
        ComPtr<ResourceAllocation> allocation;
        EXPECT_SIZE_CACHE_MISS(
            resourceAllocator,
            resourceAllocator->CreateResource(
                baseAllocationDesc,
                CreateBasicBufferDesc(D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT),
                D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(),
                  static_cast<uint64_t>(D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT));
    }

    // Second request is always a cache hit.
    {
        ComPtr<ResourceAllocation> allocation;

        ALLOCATION_DESC smallResourceAllocDesc = baseAllocationDesc;
        smallResourceAllocDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;
        smallResourceAllocDesc.Flags |= ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE;

        EXPECT_SIZE_CACHE_HIT(resourceAllocator,
                              resourceAllocator->CreateResource(
                                  smallResourceAllocDesc,
                                  CreateBasicBufferDesc(D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT),
                                  D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(),
                  static_cast<uint64_t>(D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT));
    }
    {
        ComPtr<ResourceAllocation> allocation;
        EXPECT_SIZE_CACHE_HIT(resourceAllocator,
                              resourceAllocator->CreateResource(
                                  baseAllocationDesc,
                                  CreateBasicBufferDesc(D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT),
                                  D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(),
                  static_cast<uint64_t>(D3D12_DEFAULT_RESOURCE_PLACEMENT_ALIGNMENT));
    }
    {
        ComPtr<ResourceAllocation> allocation;
        EXPECT_SIZE_CACHE_HIT(
            resourceAllocator,
            resourceAllocator->CreateResource(
                baseAllocationDesc,
                CreateBasicBufferDesc(D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT),
                D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_EQ(allocation->GetSize(),
                  static_cast<uint64_t>(D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT));
    }
}

// Verify two buffers, with and without padding, allocate the correct size.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferWithPadding) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    constexpr uint64_t kBufferSize = GPGMM_MB_TO_BYTES(1);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<ResourceAllocation> allocationWithoutPadding;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kBufferSize), D3D12_RESOURCE_STATE_GENERIC_READ,
        nullptr, &allocationWithoutPadding));

    allocationDesc.RequireResourceHeapPadding = 63;
    ComPtr<ResourceAllocation> allocationWithPadding;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kBufferSize), D3D12_RESOURCE_STATE_GENERIC_READ,
        nullptr, &allocationWithPadding));

    EXPECT_GE(allocationWithPadding->GetSize() - allocationWithoutPadding->GetSize(),
              allocationDesc.RequireResourceHeapPadding);

    // Padded resources are only supported for standalone allocations.
    EXPECT_EQ(allocationWithPadding->GetMethod(), gpgmm::AllocationMethod::kStandalone);
}

// Verify two textures, with and without padding, allocate the correct size.
TEST_F(D3D12ResourceAllocatorTests, CreateTextureWithPadding) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<ResourceAllocation> allocationWithoutPadding;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        allocationDesc, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1),
        D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocationWithoutPadding));

    allocationDesc.RequireResourceHeapPadding = 63;
    ComPtr<ResourceAllocation> allocationWithPadding;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        allocationDesc, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1),
        D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocationWithPadding));

    EXPECT_GE(allocationWithPadding->GetSize() - allocationWithoutPadding->GetSize(),
              allocationDesc.RequireResourceHeapPadding);

    // Padded resources are only supported for standalone allocations.
    EXPECT_EQ(allocationWithPadding->GetMethod(), gpgmm::AllocationMethod::kStandalone);
}

TEST_F(D3D12ResourceAllocatorTests, AllocatorFeatures) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // Request information with invalid data size.
    {
        struct WrongData {
            uint64_t bigItem;
        } WrongData = {};

        ASSERT_FAILED(resourceAllocator->CheckFeatureSupport(
            ALLOCATOR_FEATURE_RESOURCE_ALLOCATION_SUPPORT, &WrongData, sizeof(WrongData)));
    }

    // Request information with no data.
    {
        ASSERT_FAILED(resourceAllocator->CheckFeatureSupport(
            ALLOCATOR_FEATURE_RESOURCE_ALLOCATION_SUPPORT, nullptr, 0));
    }

    // Request information with valid data size.
    {
        FEATURE_DATA_RESOURCE_ALLOCATION_SUPPORT data = {};
        ASSERT_SUCCEEDED(resourceAllocator->CheckFeatureSupport(
            ALLOCATOR_FEATURE_RESOURCE_ALLOCATION_SUPPORT, &data, sizeof(data)));
    }
}
