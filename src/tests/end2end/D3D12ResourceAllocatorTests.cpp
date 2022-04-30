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

#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/DefaultsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/utils/Math.h"
#include "tests/D3D12Test.h"

#include <gpgmm_d3d12.h>

#include <set>
#include <thread>

using namespace gpgmm::d3d12;

class D3D12ResourceAllocatorTests : public D3D12TestBase, public ::testing::Test {
  protected:
    void SetUp() override {
        D3D12TestBase::SetUp();
    }

    void TearDown() override {
        D3D12TestBase::TearDown();
    }
};

TEST_F(D3D12ResourceAllocatorTests, CreateAllocator) {
    // Creating an invalid allocator should always fail.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_FAILED(ResourceAllocator::CreateAllocator({}, &resourceAllocator));
        EXPECT_EQ(resourceAllocator, nullptr);
    }

    // Creating an allocator without a device should always fail.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.Device = nullptr;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_FAILED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
        EXPECT_EQ(resourceAllocator, nullptr);
    }

    // Creating an allocator without an adapter should always fail.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.Adapter = nullptr;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_FAILED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
        EXPECT_EQ(resourceAllocator, nullptr);
    }

    // Creating a new allocator using the defaults should always succeed.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(
            ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
        EXPECT_NE(resourceAllocator, nullptr);
    }

    // Creating a new allocator with a preferred resource heap size larger then the max resource
    // heap size should always fail.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.PreferredResourceHeapSize = kDefaultPreferredResourceHeapSize;
        desc.MaxResourceHeapSize = kDefaultPreferredResourceHeapSize / 2;

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_FAILED(ResourceAllocator::CreateAllocator(desc, &resourceAllocator));
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

// Exceeding the max resource heap size should always fail.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferOversized) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    constexpr uint64_t kOversizedBuffer = 32ll * 1024ll * 1024ll * 1024ll;  // 32GB
    ComPtr<ResourceAllocation> allocation;
    ASSERT_FAILED(resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kOversizedBuffer + 1),
                                                    D3D12_RESOURCE_STATE_COMMON, nullptr,
                                                    &allocation));
    ASSERT_EQ(allocation, nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBuffer) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // Creating a resource without allocation should always fail.
    {
        ASSERT_FAILED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_COMMON, nullptr, nullptr));
    }

    // Using the min resource heap size should always succeed.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        ASSERT_NE(allocation->GetResource(), nullptr);
    }

    // Mapping the entire buffer should always succeed.
    {
        ComPtr<ResourceAllocation> allocation;
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        ASSERT_NE(allocation->GetResource(), nullptr);

        ASSERT_SUCCEEDED(allocation->Map());
    }

    // Resource per heap type should always succeed if the heap type is allowed.
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
    }
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_READBACK;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_COPY_DEST, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
    }
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
    }
    {
        ALLOCATION_DESC allocationDesc = {};
        allocationDesc.HeapType = D3D12_HEAP_TYPE_CUSTOM;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
    }

    // Creating a zero sized buffer is not allowed.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(0), D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_EQ(allocation, nullptr);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateSmallTexture) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // DXGI_FORMAT_R8G8B8A8_UNORM
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1),
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
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 1, 1, 4),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_TRUE(gpgmm::IsAligned(
            allocation->GetSize(),
            static_cast<uint32_t>(D3D12_DEFAULT_MSAA_RESOURCE_PLACEMENT_ALIGNMENT)));
    }
}

TEST_F(D3D12ResourceAllocatorTests, ImportBuffer) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    // Importing a non-existent buffer should always fail.
    ComPtr<ResourceAllocation> externalAllocation;
    ASSERT_FAILED(resourceAllocator->CreateResource(nullptr, &externalAllocation));
    ASSERT_EQ(externalAllocation, nullptr);

    // Importing a buffer without returning the allocation should always fail.
    ASSERT_FAILED(resourceAllocator->CreateResource(
        {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize), D3D12_RESOURCE_STATE_COMMON,
        nullptr, nullptr));

    // Importing a buffer should always succeed.
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize), D3D12_RESOURCE_STATE_COMMON,
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
    D3D12_RESOURCE_DESC badBufferDesc = CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize);
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

    ComPtr<ResourceAllocation> allocation;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize), D3D12_RESOURCE_STATE_COMMON,
        nullptr, &allocation));
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetSize(), kDefaultPreferredResourceHeapSize);

    // Commmitted resources cannot be backed by a D3D12 heap.
    Heap* resourceHeap = allocation->GetMemory();
    ASSERT_NE(resourceHeap, nullptr);
    ASSERT_EQ(resourceHeap->GetHeap(), nullptr);

    // Commited resources must use all the memory allocated.
    EXPECT_EQ(resourceAllocator->GetInfo().UsedMemoryUsage, kDefaultPreferredResourceHeapSize);
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
    ComPtr<ResourceAllocation> allocation;
    ASSERT_FAILED(resourceAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize + 1),
        D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
    ASSERT_EQ(allocation, nullptr);

    constexpr uint64_t bufferSize = kDefaultPreferredResourceHeapSize / 8;

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

TEST_F(D3D12ResourceAllocatorTests, CreateBufferSuballocatedWithin) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    ALLOCATION_DESC desc = {};
    desc.Flags = ALLOCATION_FLAG_ALLOW_SUBALLOCATE_WITHIN_RESOURCE;
    desc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

    constexpr uint32_t kSubAllocationSize = 4u;

    // Create two tiny buffers that will be byte-aligned.
    ComPtr<ResourceAllocation> tinyBufferAllocA;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        desc, CreateBasicBufferDesc(kSubAllocationSize), D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
        &tinyBufferAllocA));
    ASSERT_NE(tinyBufferAllocA, nullptr);
    EXPECT_EQ(tinyBufferAllocA->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    EXPECT_EQ(tinyBufferAllocA->GetSize(), kSubAllocationSize);

    ComPtr<ResourceAllocation> tinyBufferAllocB;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        desc, CreateBasicBufferDesc(kSubAllocationSize), D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
        &tinyBufferAllocB));
    ASSERT_NE(tinyBufferAllocB, nullptr);
    EXPECT_EQ(tinyBufferAllocB->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    EXPECT_EQ(tinyBufferAllocB->GetSize(), kSubAllocationSize);

    // Both buffers should be allocated in sequence, back-to-back.
    EXPECT_EQ(tinyBufferAllocA->GetOffsetFromResource() + kSubAllocationSize,
              tinyBufferAllocB->GetOffsetFromResource());

    EXPECT_EQ(tinyBufferAllocA->GetResource(), tinyBufferAllocB->GetResource());

    EXPECT_EQ(tinyBufferAllocA->GetGPUVirtualAddress() + kSubAllocationSize,
              tinyBufferAllocB->GetGPUVirtualAddress());

    // Mapping a resource allocation allocated within itself must use the entire resource.
    ASSERT_FAILED(tinyBufferAllocA->Map(1));
    ASSERT_FAILED(tinyBufferAllocB->Map(1));

    // Create another using a new heap type, it must be given it's own resource.
    desc.HeapType = D3D12_HEAP_TYPE_READBACK;

    ComPtr<ResourceAllocation> tinyBufferAllocC;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        desc, CreateBasicBufferDesc(kSubAllocationSize), D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
        &tinyBufferAllocC));
    ASSERT_NE(tinyBufferAllocC, nullptr);
    EXPECT_EQ(tinyBufferAllocC->GetMethod(), gpgmm::AllocationMethod::kSubAllocatedWithin);
    EXPECT_EQ(tinyBufferAllocC->GetSize(), kSubAllocationSize);
    EXPECT_EQ(tinyBufferAllocC->GetOffsetFromResource(), 0u);
    EXPECT_NE(tinyBufferAllocC->GetResource(), tinyBufferAllocA->GetResource());

    // Write kSubAllocationSize worth of bytes with value 0xAA in mapped subAllocation A.
    std::vector<uint8_t> dataAA(kSubAllocationSize, 0xAA);
    void* mappedBufferA = nullptr;
    ASSERT_SUCCEEDED(tinyBufferAllocA->Map(0, nullptr, &mappedBufferA));
    memcpy(mappedBufferA, dataAA.data(), dataAA.size());

    // Write kSubAllocationSize worth of bytes with value 0xBB in mapped subAllocation B.
    std::vector<uint8_t> dataBB(kSubAllocationSize, 0xBB);
    void* mappedBufferB = nullptr;
    ASSERT_SUCCEEDED(tinyBufferAllocB->Map(0, nullptr, &mappedBufferB));
    memcpy(mappedBufferB, dataBB.data(), dataBB.size());

    EXPECT_NE(mappedBufferA, mappedBufferB);

    // Map the entire buffer and check both allocated ranges.
    void* mappedBuffer = nullptr;
    ASSERT_SUCCEEDED(tinyBufferAllocB->GetResource()->Map(0, nullptr, &mappedBuffer));

    const uint8_t* mappedByte = static_cast<uint8_t*>(mappedBuffer);
    for (uint32_t i = 0; i < kSubAllocationSize; i++, mappedByte++) {
        EXPECT_EQ(*mappedByte, 0xAA);
    }

    for (uint32_t i = 0; i < kSubAllocationSize; i++, mappedByte++) {
        EXPECT_EQ(*mappedByte, 0xBB);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferNeverSubAllocated) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    constexpr uint64_t bufferSize = kDefaultPreferredResourceHeapSize / 2;

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

    constexpr uint64_t bufferSize = kDefaultPreferredResourceHeapSize;

    // Create the first buffer.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            baseAllocationDesc, CreateBasicBufferDesc(bufferSize * 2),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_NE(allocation->GetResource(), nullptr);
        EXPECT_EQ(allocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }

    // Check the first buffer was not pool-allocated by creating it again.
    {
        ALLOCATION_DESC allocationDesc = baseAllocationDesc;
        allocationDesc.Flags = ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;

        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(resourceAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(bufferSize * 2),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
    }

    // Create another buffer.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            baseAllocationDesc, CreateBasicBufferDesc(bufferSize * 3),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        EXPECT_NE(allocation->GetResource(), nullptr);
        EXPECT_EQ(allocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);
    }

    // Check the second buffer was not pool-allocated by creating it again.
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
    constexpr uint64_t bufferSize = kDefaultPreferredResourceHeapSize;

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

    // Release the pooled resource heaps.
    poolAllocator->Trim();

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

        ComPtr<ResourceAllocation> firstAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &firstAllocation));
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);

        RESOURCE_ALLOCATOR_INFO info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 1u);
        EXPECT_EQ(info.UsedMemoryUsage, kDefaultPreferredResourceHeapSize);
    }

    // Calculate info for two pooled standalone allocations.
    {
        ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        ALLOCATION_DESC standaloneAllocationDesc = {};
        standaloneAllocationDesc.Flags = ALLOCATION_FLAG_NEVER_SUBALLOCATE_MEMORY;

        ComPtr<ResourceAllocation> firstAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &firstAllocation));
        ASSERT_NE(firstAllocation, nullptr);
        EXPECT_EQ(firstAllocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);

        RESOURCE_ALLOCATOR_INFO info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 1u);
        EXPECT_EQ(info.UsedMemoryUsage, kDefaultPreferredResourceHeapSize);

        ComPtr<ResourceAllocation> secondAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            standaloneAllocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &secondAllocation));
        ASSERT_NE(secondAllocation, nullptr);
        EXPECT_EQ(secondAllocation->GetMethod(), gpgmm::AllocationMethod::kStandalone);

        info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 2u);
        EXPECT_EQ(info.UsedMemoryUsage, kDefaultPreferredResourceHeapSize * 2);
    }

    // Calculate info for two sub-allocations.
    {
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(
            ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
        ASSERT_NE(resourceAllocator, nullptr);

        constexpr uint64_t kBufferSize = kDefaultPreferredResourceHeapSize / 8;
        ComPtr<ResourceAllocation> firstAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferSize),
                                                           D3D12_RESOURCE_STATE_GENERIC_READ,
                                                           nullptr, &firstAllocation));
        ASSERT_NE(firstAllocation, nullptr);

        // Depending on the device, sub-allocation could fail. Since this test relies on a
        // sub-allocator's info counts, it must be skipped.
        // TODO: Consider testing counts by allocator type.
        GPGMM_SKIP_TEST_IF(firstAllocation->GetMethod() != gpgmm::AllocationMethod::kSubAllocated);

        RESOURCE_ALLOCATOR_INFO info = resourceAllocator->GetInfo();
        EXPECT_EQ(info.UsedMemoryCount, 1u);
        EXPECT_EQ(info.UsedMemoryUsage, kDefaultPreferredResourceHeapSize);
        EXPECT_EQ(info.UsedBlockCount, 1u);
        EXPECT_GE(info.UsedBlockUsage, kBufferSize);

        ComPtr<ResourceAllocation> secondAllocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource({}, CreateBasicBufferDesc(kBufferSize),
                                                           D3D12_RESOURCE_STATE_GENERIC_READ,
                                                           nullptr, &secondAllocation));
        ASSERT_NE(secondAllocation, nullptr);
        EXPECT_EQ(secondAllocation->GetMethod(), gpgmm::AllocationMethod::kSubAllocated);

        info = resourceAllocator->GetInfo();
        EXPECT_GE(info.UsedMemoryCount, 1u);
        EXPECT_GE(info.UsedMemoryUsage, kDefaultPreferredResourceHeapSize);
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
            allocationWithinDesc, CreateBasicBufferDesc(kBufferSize),
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
            allocationWithinDesc, CreateBasicBufferDesc(kBufferSize),
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

    // Check the first small texture of size A cannot be reused when creating a larger texture of
    // size B.
    {
        ComPtr<ResourceAllocation> thirdAllocation;
        ASSERT_FAILED(poolAllocator->CreateResource(
            reusePoolOnlyDesc, CreateBasicTextureDesc(DXGI_FORMAT_R8G8B8A8_UNORM, 128, 128),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &thirdAllocation));
        ASSERT_EQ(thirdAllocation, nullptr);
    }
}

// Creates a bunch of small buffers using the smallest size allowed so GPU memory is pre-fetched.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferMany) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    constexpr uint64_t kNumOfBuffers = 1000u;

    std::set<ComPtr<ResourceAllocation>> allocs = {};
    for (uint64_t i = 0; i < kNumOfBuffers; i++) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(1), D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        allocs.insert(allocation);
    }

    allocs.clear();
}

// Creates a bunch of small buffers using the smallest size allowed so GPU memory is pre-fetched.
TEST_F(D3D12ResourceAllocatorTests, CreateBufferManyPrefetch) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
        CreateBasicAllocatorDesc(/*enablePrefetch*/ true), &resourceAllocator));
    ASSERT_NE(resourceAllocator, nullptr);

    constexpr uint64_t kNumOfBuffers = 1000u;

    std::set<ComPtr<ResourceAllocation>> allocs = {};
    for (uint64_t i = 0; i < kNumOfBuffers; i++) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(1), D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
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

    constexpr uint32_t kThreadCount = 64u;
    std::vector<std::thread> threads(kThreadCount);
    for (size_t threadIdx = 0; threadIdx < threads.size(); threadIdx++) {
        threads[threadIdx] = std::thread([&]() {
            ComPtr<ResourceAllocation> allocation;
            ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
                {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
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

    constexpr uint32_t kSubAllocationSize = 4u;

    constexpr uint32_t kThreadCount = 64u;
    std::vector<std::thread> threads(kThreadCount);
    for (size_t threadIdx = 0; threadIdx < threads.size(); threadIdx++) {
        threads[threadIdx] = std::thread([&]() {
            ComPtr<ResourceAllocation> allocation;
            ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
                allocationDesc, CreateBasicBufferDesc(kSubAllocationSize),
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
