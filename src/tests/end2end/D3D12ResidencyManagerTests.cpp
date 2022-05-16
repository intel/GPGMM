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

#include <vector>

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
    ComPtr<ResidencyManager> residencyManager;
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(),
                                                        &resourceAllocator, &residencyManager));
    ASSERT_NE(resourceAllocator, nullptr);
    EXPECT_NE(residencyManager, nullptr);
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

// Keeps allocating until it goes over budget.
TEST_F(D3D12ResidencyManagerTests, OverBudget) {
    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
    allocatorDesc.Budget = 10 * 1024 * 1024;  // 10MB

    ComPtr<ResidencyManager> residencyManager;
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(
        ResourceAllocator::CreateAllocator(allocatorDesc, &resourceAllocator, &residencyManager));

    DXGI_QUERY_VIDEO_MEMORY_INFO* local =
        residencyManager->GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_LOCAL);
    DXGI_QUERY_VIDEO_MEMORY_INFO* nonLocal =
        residencyManager->GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL);

    std::vector<ComPtr<ResourceAllocation>> allocations = {};
    std::vector<Heap*> resourceHeaps = {};

    // Keep allocating until we go over our 10MB budget.
    while (local->Budget > local->CurrentUsage || nonLocal->Budget > nonLocal->CurrentUsage) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(1), D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        resourceHeaps.push_back(allocation->GetMemory());
        allocations.push_back(std::move(allocation));

        // Call ExecuteCommandLists() to update the budget and current usage.
        ASSERT_SUCCEEDED(residencyManager->ExecuteCommandLists(nullptr, nullptr, nullptr, 0));
    }

    ASSERT_GT(resourceHeaps.size(), 1u);

    // When over-budget, the resource heap size should remain the same.
    EXPECT_EQ(resourceHeaps.at(allocations.size() - 1)->GetSize(),
              resourceHeaps.at(allocations.size() - 2)->GetSize());
}
