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

#include "src/tests/D3D12Test.h"

#include "src/d3d12/DefaultsD3D12.h"
#include "src/d3d12/UtilsD3D12.h"

#include <gpgmm_d3d12.h>

using namespace gpgmm::d3d12;

class D3D12ResourceAllocatorTests : public D3D12TestBase, public ::testing::Test {
  protected:
    void SetUp() override {
        D3D12TestBase::SetUp();

        ASSERT_SUCCEEDED(
            ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &mDefaultAllocator));
        ASSERT_NE(mDefaultAllocator, nullptr);
    }

    void TearDown() override {
        mDefaultAllocator = nullptr;
        D3D12TestBase::TearDown();
    }

    static D3D12_RESOURCE_DESC CreateBasicBufferDesc(uint64_t width) {
        D3D12_RESOURCE_DESC resourceDesc;
        resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        resourceDesc.Alignment = 0;
        resourceDesc.Width = width;
        resourceDesc.Height = 1;
        resourceDesc.DepthOrArraySize = 1;
        resourceDesc.MipLevels = 1;
        resourceDesc.Format = DXGI_FORMAT_UNKNOWN;
        resourceDesc.SampleDesc.Count = 1;
        resourceDesc.SampleDesc.Quality = 0;
        resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        resourceDesc.Flags = D3D12_RESOURCE_FLAG_NONE;
        return resourceDesc;
    }

    ComPtr<ResourceAllocator> mDefaultAllocator;
};

TEST_F(D3D12ResourceAllocatorTests, CreateAllocatorBasic) {
    // Creating an invalid allocator should always fail.
    {
        ComPtr<ResourceAllocator> allocator;
        ASSERT_FAILED(ResourceAllocator::CreateAllocator({}, &allocator));
        ASSERT_EQ(allocator, nullptr);
    }

    // Creating an allocator without a device should always fail.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.Device = nullptr;

        ComPtr<ResourceAllocator> allocator;
        ASSERT_FAILED(ResourceAllocator::CreateAllocator(desc, &allocator));
        ASSERT_EQ(allocator, nullptr);
    }

    // Creating an allocator without an adapter should always fail.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        desc.Adapter = nullptr;

        ComPtr<ResourceAllocator> allocator;
        ASSERT_FAILED(ResourceAllocator::CreateAllocator(desc, &allocator));
        ASSERT_EQ(allocator, nullptr);
    }

    // Creating a new allocator based on the default should always succeed.
    {
        ComPtr<ResourceAllocator> allocator;
        ASSERT_SUCCEEDED(
            ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &allocator));
        ASSERT_NE(allocator, nullptr);
        ASSERT_NE(allocator, mDefaultAllocator);
    }
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferBasic) {
    // Creating a resource without allocation should always fail.
    ASSERT_FAILED(mDefaultAllocator->CreateResource(
        {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize), D3D12_RESOURCE_STATE_COMMON,
        nullptr, nullptr));

    // Exceeding the max resource heap size should always fail.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_FAILED(mDefaultAllocator->CreateResource(
            {}, CreateBasicBufferDesc(kDefaultMaxResourceHeapSize + 1), D3D12_RESOURCE_STATE_COMMON,
            nullptr, &allocation));
        ASSERT_EQ(allocation, nullptr);
    }

    // Using the min resource heap size should always succeed.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(mDefaultAllocator->CreateResource(
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

        ASSERT_SUCCEEDED(mDefaultAllocator->CreateResource(
            allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        ASSERT_NE(allocation->GetResource(), nullptr);

        ASSERT_SUCCEEDED(allocation->Map());
    }
}

TEST_F(D3D12ResourceAllocatorTests, ImportBuffer) {
    // Importing a non-existent buffer should always fail.
    ComPtr<ResourceAllocation> externalAllocation;
    ASSERT_FAILED(mDefaultAllocator->CreateResource(nullptr, &externalAllocation));
    ASSERT_EQ(externalAllocation, nullptr);

    // Importing a buffer without returning the allocation should always fail.
    ASSERT_FAILED(mDefaultAllocator->CreateResource(
        {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize), D3D12_RESOURCE_STATE_COMMON,
        nullptr, nullptr));

    // Importing a buffer should always succeed.
    ASSERT_SUCCEEDED(mDefaultAllocator->CreateResource(
        {}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize), D3D12_RESOURCE_STATE_COMMON,
        nullptr, &externalAllocation));
    ASSERT_NE(externalAllocation, nullptr);

    ComPtr<ResourceAllocation> internalAllocation;
    ASSERT_SUCCEEDED(
        mDefaultAllocator->CreateResource(externalAllocation->GetResource(), &internalAllocation));
    ASSERT_NE(internalAllocation, nullptr);

    // Underlying resource must stay the same.
    ASSERT_EQ(internalAllocation->GetResource(), externalAllocation->GetResource());
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferInvalidDesc) {
    // Garbage buffer descriptor should always fail.
    D3D12_RESOURCE_DESC badBufferDesc = CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize);
    badBufferDesc.Flags = static_cast<D3D12_RESOURCE_FLAGS>(0xFF);

    ComPtr<ResourceAllocation> allocation;
    ASSERT_FAILED(mDefaultAllocator->CreateResource({}, badBufferDesc, D3D12_RESOURCE_STATE_COMMON,
                                                    nullptr, &allocation));
    ASSERT_EQ(allocation, nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferAlwaysCommittedFlag) {
    ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
    desc.Flags = ALLOCATOR_FLAG_ALWAYS_COMMITED;

    ComPtr<ResourceAllocator> allocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(desc, &allocator));
    ASSERT_NE(allocator, nullptr);

    ComPtr<ResourceAllocation> allocation;
    ASSERT_SUCCEEDED(
        allocator->CreateResource({}, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize),
                                  D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
    ASSERT_NE(allocation, nullptr);
    EXPECT_EQ(allocation->GetSize(), kDefaultPreferredResourceHeapSize);

    // Commmitted resources cannot be backed by a D3D12 heap.
    Heap* resourceHeap = static_cast<Heap*>(allocation->GetMemory());
    ASSERT_NE(resourceHeap, nullptr);
    ASSERT_EQ(resourceHeap->GetHeap(), nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferNeverAllocate) {
    // Check we can't reuse memory if CreateResource was never called previously.
    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.Flags = ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
    ComPtr<ResourceAllocation> allocation;
    ASSERT_FAILED(mDefaultAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize + 1),
        D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
    ASSERT_EQ(allocation, nullptr);

    allocationDesc.Flags = ALLOCATION_FLAG_NONE;
    ComPtr<ResourceAllocation> allocationA;
    ASSERT_SUCCEEDED(mDefaultAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize / 2),
        D3D12_RESOURCE_STATE_COMMON, nullptr, &allocationA));
    ASSERT_NE(allocationA, nullptr);
    EXPECT_EQ(allocationA->GetSize(), kDefaultPreferredResourceHeapSize / 2);

    // Re-check that the same resource heap is used once CreateResource gets called.
    allocationDesc.Flags = ALLOCATION_FLAG_NEVER_ALLOCATE_MEMORY;
    ComPtr<ResourceAllocation> allocationB;
    ASSERT_SUCCEEDED(mDefaultAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize / 2),
        D3D12_RESOURCE_STATE_COMMON, nullptr, &allocationB));
    ASSERT_NE(allocationB, nullptr);
    EXPECT_EQ(allocationB->GetSize(), kDefaultPreferredResourceHeapSize / 2);

    // Must fail since the first resource heap is full and another CreateResource cannot allocate.
    ComPtr<ResourceAllocation> allocationC;
    ASSERT_FAILED(mDefaultAllocator->CreateResource(
        allocationDesc, CreateBasicBufferDesc(kDefaultPreferredResourceHeapSize / 2),
        D3D12_RESOURCE_STATE_COMMON, nullptr, &allocationC));
    ASSERT_EQ(allocationC, nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferSuballocatedWithin) {
    ALLOCATION_DESC desc = {};
    desc.Flags = ALLOCATION_FLAG_SUBALLOCATE_WITHIN_RESOURCE;
    desc.HeapType = D3D12_HEAP_TYPE_UPLOAD;

    constexpr uint32_t kSubAllocationSize = 4u;

    // Create two tiny buffers that will be byte-aligned.
    ComPtr<ResourceAllocation> tinyBufferAllocA;
    ASSERT_SUCCEEDED(mDefaultAllocator->CreateResource(
        desc, CreateBasicBufferDesc(kSubAllocationSize), D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
        &tinyBufferAllocA));
    ASSERT_NE(tinyBufferAllocA, nullptr);
    EXPECT_EQ(tinyBufferAllocA->GetSize(), kSubAllocationSize);

    ComPtr<ResourceAllocation> tinyBufferAllocB;
    ASSERT_SUCCEEDED(mDefaultAllocator->CreateResource(
        desc, CreateBasicBufferDesc(kSubAllocationSize), D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
        &tinyBufferAllocB));
    ASSERT_NE(tinyBufferAllocB, nullptr);
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
    ASSERT_SUCCEEDED(mDefaultAllocator->CreateResource(
        desc, CreateBasicBufferDesc(kSubAllocationSize), D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
        &tinyBufferAllocC));
    ASSERT_NE(tinyBufferAllocC, nullptr);
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
