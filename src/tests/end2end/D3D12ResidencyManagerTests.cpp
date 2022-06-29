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

#include "gpgmm/common/SizeClass.h"

#include <gpgmm_d3d12.h>

#include <vector>

using namespace gpgmm::d3d12;

static constexpr uint64_t kDefaultBudget = GPGMM_MB_TO_BYTES(10);

class D3D12ResidencyManagerTests : public D3D12TestBase, public ::testing::Test {
  protected:
    void SetUp() override {
        D3D12TestBase::SetUp();
    }

    void TearDown() override {
        D3D12TestBase::TearDown();
    }

    // Configures allocator for testing residency in a controlled and predictable
    // fashion.
    ALLOCATOR_DESC CreateBasicAllocatorDesc() const {
        ALLOCATOR_DESC desc = D3D12TestBase::CreateBasicAllocatorDesc();

        // Disable pre-fetching since it will could cause over-committment unpredictably.
        desc.Flags |= gpgmm::d3d12::ALLOCATOR_FLAG_DISABLE_MEMORY_PREFETCH;

        // Require MakeResident/Evict occur near CreateResource, for debugging purposes.
        desc.Flags |= gpgmm::d3d12::ALLOCATOR_FLAG_ALWAYS_IN_BUDGET;

        return desc;
    }

    RESIDENCY_DESC CreateBasicResidencyDesc(uint64_t budget) const {
        RESIDENCY_DESC residencyDesc = {};

        // Disable automatic budget updates, since it occurs uncontrollably by the OS.
        residencyDesc.UpdateBudgetByPolling = true;

        // Specify a restricted budget, the OS budget fluctuates unpredicatbly.
        residencyDesc.Budget = budget;

        // Required
        residencyDesc.IsUMA = mIsUMA;
        residencyDesc.Adapter = mAdapter;
        residencyDesc.Device = mDevice;

        return residencyDesc;
    }

    bool IsOverBudget(ResidencyManager* residencyManager) const {
        ASSERT(residencyManager != nullptr);

        DXGI_QUERY_VIDEO_MEMORY_INFO* local =
            residencyManager->GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_LOCAL);

        DXGI_QUERY_VIDEO_MEMORY_INFO* nonLocal =
            residencyManager->GetVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL);

        return local->Budget <= local->CurrentUsage && nonLocal->Budget <= nonLocal->CurrentUsage;
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

    // Re-inserting allocation between two sets should always succeed.
    {
        ResidencySet setA;
        ASSERT_SUCCEEDED(setA.Insert(allocation->GetMemory()));
        ResidencySet setB(setA);
        EXPECT_EQ(setA.Insert(allocation->GetMemory()), S_FALSE);
        ResidencySet setC;
        EXPECT_EQ(setC.Insert(allocation->GetMemory()), S_OK);
    }
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyManager) {
    // Create allocator with residency support, together.
    {
        ComPtr<ResidencyManager> residencyManager;
        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(),
                                                            &resourceAllocator, &residencyManager));
        EXPECT_NE(resourceAllocator, nullptr);
        EXPECT_NE(residencyManager, nullptr);
    }

    // Create allocator with residency, seperately.
    {
        ComPtr<ResidencyManager> residencyManager;
        ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(
            CreateBasicResidencyDesc(kDefaultBudget), &residencyManager));

        ComPtr<ResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
            CreateBasicAllocatorDesc(), residencyManager.Get(), &resourceAllocator));
        EXPECT_NE(resourceAllocator, nullptr);
        EXPECT_NE(residencyManager, nullptr);
    }
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyManagerNoLeak) {
    GPGMM_TEST_MEMORY_LEAK_START();

    // Create allocator with residency support, together.
    {
        ComPtr<ResidencyManager> residencyManager;
        ComPtr<ResourceAllocator> resourceAllocator;
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), &resourceAllocator,
                                           &residencyManager);
    }

    // Create allocator with residency, seperately.
    {
        ComPtr<ResidencyManager> residencyManager;
        ResidencyManager::CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget),
                                                 &residencyManager);

        ComPtr<ResourceAllocator> resourceAllocator;
        ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(), residencyManager.Get(),
                                           &resourceAllocator);
    }

    GPGMM_TEST_MEMORY_LEAK_END();
}

// Keeps allocating until it goes over the limited |kDefaultBudget| size budget.
TEST_F(D3D12ResidencyManagerTests, OverBudget) {
    RESIDENCY_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);

    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(residencyDesc, &residencyManager));

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
        CreateBasicAllocatorDesc(), residencyManager.Get(), &resourceAllocator));

    std::vector<ComPtr<ResourceAllocation>> allocations = {};
    while (!IsOverBudget(residencyManager.Get())) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(1), D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        allocations.push_back(std::move(allocation));
        ASSERT_SUCCEEDED(residencyManager->UpdateVideoMemorySegments());
    }
}

// Keeps allocating until it goes over the OS limited budget.
TEST_F(D3D12ResidencyManagerTests, OverBudgetUsingBudgetNotifications) {
    constexpr uint64_t kBudgetIsDeterminedByOS = 0;
    RESIDENCY_DESC residencyDesc = CreateBasicResidencyDesc(kBudgetIsDeterminedByOS);
    residencyDesc.UpdateBudgetByPolling = false;

    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(residencyDesc, &residencyManager));

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
        CreateBasicAllocatorDesc(), residencyManager.Get(), &resourceAllocator));

    // Keep allocating until we reach the budget.
    std::vector<ComPtr<ResourceAllocation>> allocations = {};
    while (!IsOverBudget(residencyManager.Get())) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource({}, CreateBasicBufferDesc(GPGMM_MB_TO_BYTES(1)),
                                              D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        allocations.push_back(std::move(allocation));
    }
}

// Keeps allocating until it goes over budget.
TEST_F(D3D12ResidencyManagerTests, OverBudgetAndNoGrowth) {
    RESIDENCY_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);

    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(residencyDesc, &residencyManager));

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
        CreateBasicAllocatorDesc(), residencyManager.Get(), &resourceAllocator));

    std::vector<ComPtr<ResourceAllocation>> allocations = {};
    std::vector<Heap*> resourceHeaps = {};

    while (!IsOverBudget(residencyManager.Get())) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, CreateBasicBufferDesc(1), D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        resourceHeaps.push_back(allocation->GetMemory());
        allocations.push_back(std::move(allocation));

        ASSERT_SUCCEEDED(residencyManager->UpdateVideoMemorySegments());
    }

    // With no budget left, the last resource heap size should not increase.
    ASSERT_GT(resourceHeaps.size(), 1u);
    EXPECT_LE(resourceHeaps.at(allocations.size() - 1)->GetSize(),
              resourceHeaps.at(allocations.size() - 2)->GetSize());
}
