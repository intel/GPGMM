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

#include "src/common/Limits.h"
#include "src/tests/D3D12Test.h"

#include <gpgmm_d3d12.h>
#include <memory>

using namespace gpgmm::d3d12;

#define ASSERT_ERROR(expr) ASSERT_TRUE(FAILED(expr))
#define ASSERT_SUCCESS(expr) ASSERT_TRUE(SUCCEEDED(expr))

class D3D12ResourceAllocatorTests : public D3D12TestBase, public ::testing::Test {
  protected:
    void SetUp() override {
        D3D12TestBase::SetUp();

        ASSERT_SUCCESS(CreateAllocator(CreateBasicAllocatorDesc(), mDefaultAllocator));
        ASSERT_NE(mDefaultAllocator, nullptr);
    }

    static HRESULT CreateAllocator(const ALLOCATOR_DESC& desc,
                                   std::unique_ptr<ResourceAllocator>& resourceAllocatorOut) {
        ResourceAllocator* resourceAllocator = nullptr;
        HRESULT hr = ResourceAllocator::CreateAllocator(desc, &resourceAllocator);
        if (FAILED(hr)) {
            return hr;
        }
        resourceAllocatorOut = std::unique_ptr<ResourceAllocator>(resourceAllocator);
        return hr;
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

    std::unique_ptr<ResourceAllocator> mDefaultAllocator;
};

TEST_F(D3D12ResourceAllocatorTests, CreateAllocator) {
    // Creating an empty allocator should fail.
    std::unique_ptr<ResourceAllocator> allocator;
    ASSERT_ERROR(CreateAllocator({}, /*out*/ allocator));
    ASSERT_EQ(allocator, nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferMinMaxHeap) {
    // Exceeding the max resource heap size should always fail.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_ERROR(mDefaultAllocator->CreateResource(
            {}, CreateBasicBufferDesc(gpgmm::kDefaultMaxHeapSize + 1), D3D12_RESOURCE_STATE_COMMON,
            nullptr, &allocation));
        ASSERT_EQ(allocation, nullptr);
    }

    // Using the min resource heap size should always succeed.
    {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCESS(
            mDefaultAllocator->CreateResource({}, CreateBasicBufferDesc(gpgmm::kDefaultMinHeapSize),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        ASSERT_NE(allocation, nullptr);
        ASSERT_NE(allocation->GetResource(), nullptr);
    }
}

TEST_F(D3D12ResourceAllocatorTests, ImportBuffer) {
    // Importing a non-existent buffer should always fail.
    ComPtr<ResourceAllocation> externalAllocation;
    ASSERT_ERROR(mDefaultAllocator->CreateResource(nullptr, &externalAllocation));
    ASSERT_EQ(externalAllocation, nullptr);

    // Importing a buffer should always succeed.
    ASSERT_SUCCESS(mDefaultAllocator->CreateResource(
        {}, CreateBasicBufferDesc(gpgmm::kDefaultMinHeapSize), D3D12_RESOURCE_STATE_COMMON, nullptr,
        &externalAllocation));
    ASSERT_NE(externalAllocation, nullptr);

    ComPtr<ResourceAllocation> internalAllocation;
    ASSERT_SUCCESS(
        mDefaultAllocator->CreateResource(externalAllocation->GetResource(), &internalAllocation));
    ASSERT_NE(internalAllocation, nullptr);

    // Underlying resource must stay the same.
    ASSERT_EQ(internalAllocation->GetResource(), externalAllocation->GetResource());
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferInvalidDesc) {
    // Garbage buffer descriptor should always fail.
    D3D12_RESOURCE_DESC badBufferDesc = CreateBasicBufferDesc(gpgmm::kDefaultMinHeapSize);
    badBufferDesc.Flags = static_cast<D3D12_RESOURCE_FLAGS>(0xFF);

    ComPtr<ResourceAllocation> allocation;
    ASSERT_ERROR(mDefaultAllocator->CreateResource({}, badBufferDesc, D3D12_RESOURCE_STATE_COMMON,
                                                   nullptr, &allocation));
    ASSERT_EQ(allocation, nullptr);
}

TEST_F(D3D12ResourceAllocatorTests, CreateBufferAlwaysCommittedFlag) {
    ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
    desc.Flags = ALLOCATOR_ALWAYS_COMMITED;

    std::unique_ptr<ResourceAllocator> allocator;
    ASSERT_SUCCESS(CreateAllocator(desc, /*out*/ allocator));
    ASSERT_NE(allocator, nullptr);

    ComPtr<ResourceAllocation> allocation;
    ASSERT_SUCCESS(allocator->CreateResource({}, CreateBasicBufferDesc(gpgmm::kDefaultMinHeapSize),
                                             D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
    ASSERT_NE(allocation, nullptr);

    // Commmitted resources cannot be backed by a D3D12 heap.
    gpgmm::d3d12::Heap* resourceHeap = static_cast<gpgmm::d3d12::Heap*>(allocation->GetMemory());
    ASSERT_NE(resourceHeap, nullptr);
    ASSERT_EQ(resourceHeap->GetD3D12Heap(), nullptr);
}
