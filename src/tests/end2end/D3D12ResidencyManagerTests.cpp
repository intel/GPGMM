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

        // Disable memory growth so older heap being paged out are the same size as newer heaps
        // being paged-in, and the test expectation based on these sizes is easy to determine.
        desc.MemoryGrowthFactor = 1.0;

        return desc;
    }

    // Configures residency manager for testing residency in a controlled and predictable
    // fashion.
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

        residencyDesc.MinLogLevel = GetMessageSeverity(GetLogLevel());

        if (IsDumpAllEventsEnabled()) {
            residencyDesc.RecordOptions.Flags |= EVENT_RECORD_FLAG_ALL_EVENTS;
            residencyDesc.RecordOptions.MinMessageLevel = residencyDesc.MinLogLevel;
            residencyDesc.RecordOptions.UseDetailedTimingEvents = true;
        }

        return residencyDesc;
    }

    uint64_t GetBudgetLeft(ResidencyManager* residencyManager,
                           const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        DXGI_QUERY_VIDEO_MEMORY_INFO* segment =
            residencyManager->GetVideoMemoryInfo(memorySegmentGroup);
        return (segment->Budget > segment->CurrentUsage) ? (segment->Budget - segment->CurrentUsage)
                                                         : 0;
    }
};

TEST_F(D3D12ResidencyManagerTests, CreateResourceHeap) {
    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(
        CreateBasicResidencyDesc(kDefaultBudget), &residencyManager));

    constexpr uint64_t kHeapSize = GPGMM_MB_TO_BYTES(10);

    D3D12_HEAP_PROPERTIES heapProperties = {};
    heapProperties.Type = D3D12_HEAP_TYPE_DEFAULT;

    D3D12_HEAP_DESC heapDesc = {};
    heapDesc.Properties = heapProperties;
    heapDesc.SizeInBytes = kHeapSize;

    auto createHeapFn = [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
        ComPtr<ID3D12Heap> heap;
        if (FAILED(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap)))) {
            return E_FAIL;
        }
        *ppPageableOut = heap.Detach();
        return S_OK;
    };

    HEAP_DESC resourceHeapDesc = {};
    resourceHeapDesc.SizeInBytes = kHeapSize;
    resourceHeapDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ASSERT_SUCCEEDED(
        Heap::CreateHeap(resourceHeapDesc, residencyManager.Get(), createHeapFn, nullptr));

    ComPtr<Heap> resourceHeap;
    ASSERT_SUCCEEDED(
        Heap::CreateHeap(resourceHeapDesc, residencyManager.Get(), createHeapFn, &resourceHeap));
    ASSERT_NE(resourceHeap, nullptr);

    EXPECT_EQ(residencyManager->GetInfo().ResidentMemoryUsage, kHeapSize);
    EXPECT_EQ(residencyManager->GetInfo().ResidentMemoryCount, 1u);

    ComPtr<ID3D12Heap> heap;
    resourceHeap.As(&heap);

    EXPECT_NE(heap, nullptr);

    ASSERT_SUCCEEDED(residencyManager->LockHeap(resourceHeap.Get()));

    EXPECT_EQ(residencyManager->GetInfo().ResidentMemoryUsage, kHeapSize);
    EXPECT_EQ(residencyManager->GetInfo().ResidentMemoryCount, 1u);

    ASSERT_SUCCEEDED(residencyManager->UnlockHeap(resourceHeap.Get()));

    EXPECT_EQ(residencyManager->GetInfo().ResidentMemoryUsage, kHeapSize);
    EXPECT_EQ(residencyManager->GetInfo().ResidentMemoryCount, 1u);

    ASSERT_FAILED(residencyManager->UnlockHeap(resourceHeap.Get()));  // Not locked
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyList) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(),
                                                        &resourceAllocator, nullptr));

    ComPtr<ResourceAllocation> allocation;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        {}, CreateBasicBufferDesc(1), D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

    // Inserting a non-existant heap should always fail
    {
        ResidencyList list;
        Heap* invalid = nullptr;
        ASSERT_FAILED(list.Add(invalid));
    }

    // Inserting from a valid allocation should always succeed.
    {
        ResidencyList list;
        ASSERT_SUCCEEDED(list.Add(allocation->GetMemory()));
        ASSERT_SUCCEEDED(list.Add(allocation->GetMemory()));
    }

    // Re-inserting allocation between two sets should always succeed.
    {
        ResidencyList listA;
        ASSERT_SUCCEEDED(listA.Add(allocation->GetMemory()));
        ResidencyList listB(listA);
        EXPECT_EQ(listB.Add(allocation->GetMemory()), S_OK);
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

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    ALLOCATION_DESC bufferAllocationDesc = {};
    bufferAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    const DXGI_MEMORY_SEGMENT_GROUP bufferMemorySegment =
        residencyManager->GetMemorySegmentGroup(bufferAllocationDesc.HeapType);
    const uint64_t memoryUnderBudget = GetBudgetLeft(residencyManager.Get(), bufferMemorySegment);

    // Keep allocating until we reach the budget.
    std::vector<ComPtr<ResourceAllocation>> allocationsBelowBudget = {};
    while (resourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize < memoryUnderBudget) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        allocationsBelowBudget.push_back(std::move(allocation));
    }

    // Created allocations below the budget should be resident.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_TRUE(allocation->IsResident());
    }

    // Keep allocating |kMemoryOverBudget| over the budget.
    constexpr uint64_t kMemoryOverBudget = GPGMM_MB_TO_BYTES(10);

    // Allocating the same amount over budget, where older allocations will be evicted.
    std::vector<ComPtr<ResourceAllocation>> allocationsAboveBudget = {};
    const uint64_t currentMemoryUsage = resourceAllocator->GetInfo().UsedMemoryUsage;

    while (currentMemoryUsage + kMemoryOverBudget > resourceAllocator->GetInfo().UsedMemoryUsage) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        allocationsAboveBudget.push_back(std::move(allocation));
    }

    // Created allocations above the budget should be resident.
    for (auto& allocation : allocationsAboveBudget) {
        EXPECT_TRUE(allocation->IsResident());
    }

    // Created allocations below the budget should NOT be resident.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_FALSE(allocation->IsResident());
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

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    ALLOCATION_DESC bufferAllocationDesc = {};
    bufferAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    const DXGI_MEMORY_SEGMENT_GROUP bufferMemorySegment =
        residencyManager->GetMemorySegmentGroup(bufferAllocationDesc.HeapType);

    const uint64_t memoryUnderBudget = GetBudgetLeft(residencyManager.Get(), bufferMemorySegment);

    // Keep allocating until we reach the budget.
    std::vector<ComPtr<ResourceAllocation>> allocations = {};
    while (resourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize < memoryUnderBudget) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        allocations.push_back(std::move(allocation));
    }

    // All allocations should be created resident.
    for (auto& allocation : allocations) {
        EXPECT_TRUE(allocation->IsResident());
    }
}

// Keeps allocating heaps of increasing size until it goes over budget.
TEST_F(D3D12ResidencyManagerTests, OverBudgetWithGrowth) {
    RESIDENCY_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);

    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(residencyDesc, &residencyManager));

    ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
    allocatorDesc.MemoryGrowthFactor = 2;

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
        CreateBasicAllocatorDesc(), residencyManager.Get(), &resourceAllocator));

    std::vector<ComPtr<ResourceAllocation>> allocations = {};
    std::vector<Heap*> resourceHeaps = {};

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    ALLOCATION_DESC bufferAllocationDesc = {};
    bufferAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    const DXGI_MEMORY_SEGMENT_GROUP bufferMemorySegment =
        residencyManager->GetMemorySegmentGroup(bufferAllocationDesc.HeapType);
    const uint64_t memoryUnderBudget = GetBudgetLeft(residencyManager.Get(), bufferMemorySegment);

    while (resourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize < memoryUnderBudget) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        resourceHeaps.push_back(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    // Check growth occured
    for (size_t heapIndex = 1; heapIndex < resourceHeaps.size(); heapIndex++) {
        EXPECT_LE(resourceHeaps[heapIndex - 1]->GetSize(), resourceHeaps[heapIndex]->GetSize());
    }

    // With no budget left, the last resource heap size should not increase.
    ASSERT_GT(resourceHeaps.size(), 1u);
    EXPECT_LE(resourceHeaps.at(allocations.size() - 1)->GetSize(),
              resourceHeaps.at(allocations.size() - 2)->GetSize());
}
