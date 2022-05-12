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

#include "tests/D3D12Test.h"

#include <gpgmm_d3d12.h>

using namespace gpgmm::d3d12;

class D3D12ResidencyManagerTests : public D3D12TestBase, public ::testing::Test {
  protected:
    void SetUp() override {
        D3D12TestBase::SetUp();
    }

    void TearDown() override {
        D3D12TestBase::TearDown();
    }
};

TEST_F(D3D12ResidencyManagerTests, CreateResidencySet) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(),
                                                        &resourceAllocator, nullptr));

    ComPtr<ResourceAllocation> allocation;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        {}, CreateBasicBufferDesc(1), D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

    // Inserting a non-existant heap should always fail
    {
        ResidencySet set;
        Heap* invalid = nullptr;
        ASSERT_FAILED(set.Insert(invalid));
    }

    // Inserting from a valid allocation should always succeed.
    {
        ResidencySet set;
        ASSERT_SUCCEEDED(set.Insert(allocation->GetMemory()));
        ASSERT_SUCCEEDED(set.Insert(allocation->GetMemory()));
    }
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyManager) {
    // Creating a allocator with residency should succeed with S_OK.
    {
        ComPtr<ResidencyManager> residencyManager;
        ComPtr<ResourceAllocator> resourceAllocator;
        EXPECT_HRESULT(ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(),
                                                          &resourceAllocator, &residencyManager),
                       S_OK);
    }

    // Creating a allocator with NULL residency should succeed with S_FALSE.
    {
        ALLOCATOR_DESC desc = CreateBasicAllocatorDesc();
        ComPtr<ResourceAllocator> resourceAllocator;
        EXPECT_HRESULT(ResourceAllocator::CreateAllocator(desc, &resourceAllocator, nullptr),
                       S_FALSE);
    }
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyManagerNoLeak) {
    GPGMM_TEST_MEMORY_LEAK_START();
    {
        ComPtr<ResidencyManager> residencyManager;
        ComPtr<ResourceAllocator> resourceAllocator;
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator,
                                           &residencyManager);
    }
    GPGMM_TEST_MEMORY_LEAK_END();
}
