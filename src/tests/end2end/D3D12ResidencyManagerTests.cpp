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

#include "tests/D3D12Test.h"

#include "gpgmm/common/SizeClass.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

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
        residencyDesc.Flags |= RESIDENCY_FLAG_NEVER_UPDATE_BUDGET_ON_WORKER_THREAD;

        // Specify a restricted budget, the OS budget fluctuates unpredicatbly.
        residencyDesc.MaxBudgetInBytes = budget;

        // Required
        residencyDesc.IsUMA = mCaps->IsAdapterUMA();
        residencyDesc.Adapter = mAdapter;
        residencyDesc.Device = mDevice;

        residencyDesc.MinLogLevel = GetMessageSeverity(GetLogLevel());

        if (IsDumpEventsEnabled()) {
            residencyDesc.RecordOptions.Flags |= EVENT_RECORD_FLAG_ALL_EVENTS;
            residencyDesc.RecordOptions.MinMessageLevel = residencyDesc.MinLogLevel;
            residencyDesc.RecordOptions.UseDetailedTimingEvents = true;
        }

        return residencyDesc;
    }

    uint64_t GetBudgetLeft(ResidencyManager* residencyManager,
                           const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        DXGI_QUERY_VIDEO_MEMORY_INFO segment = {};
        residencyManager->QueryVideoMemoryInfo(memorySegmentGroup, &segment);
        return (segment.Budget > segment.CurrentUsage) ? (segment.Budget - segment.CurrentUsage)
                                                       : 0;
    }
};

TEST_F(D3D12ResidencyManagerTests, CreateResourceHeapNotResident) {
    // Adapters that do not support creating heaps will ignore D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT.
    GPGMM_SKIP_TEST_IF(!mCaps->IsCreateHeapNotResidentSupported());

    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(
        CreateBasicResidencyDesc(kDefaultBudget), &residencyManager));

    constexpr uint64_t kHeapSize = GPGMM_MB_TO_BYTES(10);

    D3D12_HEAP_PROPERTIES heapProperties = {};
    heapProperties.Type = D3D12_HEAP_TYPE_DEFAULT;

    HEAP_DESC resourceHeapAlwaysInBudgetDesc = {};
    resourceHeapAlwaysInBudgetDesc.SizeInBytes = kHeapSize;
    resourceHeapAlwaysInBudgetDesc.MemorySegmentGroup = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;
    resourceHeapAlwaysInBudgetDesc.Flags |= HEAP_FLAG_ALWAYS_IN_BUDGET;

    auto createHeapNotResidentFn = [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
        D3D12_HEAP_DESC heapDesc = {};
        heapDesc.Properties = heapProperties;
        heapDesc.SizeInBytes = kHeapSize;

        // Assume tier 1, which all adapters support.
        heapDesc.Flags |= D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS;

        heapDesc.Flags |= D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT;

        ComPtr<ID3D12Heap> heap;
        if (FAILED(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap)))) {
            return E_FAIL;
        }
        *ppPageableOut = heap.Detach();
        return S_OK;
    };

    ASSERT_FAILED(Heap::CreateHeap(resourceHeapAlwaysInBudgetDesc, residencyManager.Get(),
                                   createHeapNotResidentFn, nullptr));
}

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

    // Assume tier 1, which all adapters support.
    heapDesc.Flags |= D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS;

    auto createHeapFn = [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
        ComPtr<ID3D12Heap> heap;
        if (FAILED(mDevice->CreateHeap(&heapDesc, IID_PPV_ARGS(&heap)))) {
            return E_FAIL;
        }
        *ppPageableOut = heap.Detach();
        return S_OK;
    };

    auto badCreateHeapFn = [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
        // No pageable set should E_FAIL.
        return S_OK;
    };

    HEAP_DESC resourceHeapDesc = {};
    resourceHeapDesc.SizeInBytes = kHeapSize;
    resourceHeapDesc.MemorySegmentGroup = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;

    ASSERT_FAILED(
        Heap::CreateHeap(resourceHeapDesc, residencyManager.Get(), badCreateHeapFn, nullptr));

    ASSERT_SUCCEEDED(
        Heap::CreateHeap(resourceHeapDesc, residencyManager.Get(), createHeapFn, nullptr));

    // Create a resource heap without residency.
    ComPtr<Heap> resourceHeap;
    ASSERT_SUCCEEDED(Heap::CreateHeap(resourceHeapDesc, nullptr, createHeapFn, &resourceHeap));

    // Ensure the unmanaged resource heap state is always unknown. Even though D3D12 implicitly
    // creates heaps as resident, untrack resource heaps would never transition out from
    // RESIDENCY_STATUS_CURRENT_RESIDENT and must be left RESIDENCY_STATUS_UNKNOWN.
    EXPECT_EQ(resourceHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_STATUS_UNKNOWN);
    EXPECT_EQ(resourceHeap->GetInfo().IsLocked, false);

    // Create a resource heap with residency.
    ASSERT_SUCCEEDED(
        Heap::CreateHeap(resourceHeapDesc, residencyManager.Get(), createHeapFn, &resourceHeap));
    ASSERT_NE(resourceHeap, nullptr);

    EXPECT_EQ(resourceHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_STATUS_CURRENT_RESIDENT);
    EXPECT_EQ(resourceHeap->GetInfo().IsLocked, false);

    // Residency status of resource heap types is always known.
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryUsage, resourceHeapDesc.SizeInBytes);
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryCount, 1u);

    ComPtr<ID3D12Heap> heap;
    ASSERT_SUCCEEDED(resourceHeap.As(&heap));
    EXPECT_NE(heap, nullptr);

    ASSERT_SUCCEEDED(residencyManager->LockHeap(resourceHeap.Get()));

    EXPECT_EQ(resourceHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_STATUS_CURRENT_RESIDENT);
    EXPECT_EQ(resourceHeap->GetInfo().IsLocked, true);

    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryUsage, resourceHeapDesc.SizeInBytes);
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryCount, 1u);

    ASSERT_SUCCEEDED(residencyManager->UnlockHeap(resourceHeap.Get()));

    EXPECT_EQ(resourceHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_STATUS_CURRENT_RESIDENT);
    EXPECT_EQ(resourceHeap->GetInfo().IsLocked, false);

    // Unlocking a heap does not evict it, the memory usage should not change.
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryUsage, resourceHeapDesc.SizeInBytes);
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryCount, 1u);

    ASSERT_FAILED(residencyManager->UnlockHeap(resourceHeap.Get()));  // Not locked
}

TEST_F(D3D12ResidencyManagerTests, CreateDescriptorHeap) {
    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(
        CreateBasicResidencyDesc(kDefaultBudget), &residencyManager));

    D3D12_DESCRIPTOR_HEAP_DESC heapDesc = {};
    heapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    heapDesc.NumDescriptors = 1;
    heapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;

    HEAP_DESC descriptorHeapDesc = {};
    descriptorHeapDesc.SizeInBytes =
        heapDesc.NumDescriptors * mDevice->GetDescriptorHandleIncrementSize(heapDesc.Type);
    descriptorHeapDesc.MemorySegmentGroup = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;

    auto createHeapFn = [&](ID3D12Pageable** ppPageableOut) -> HRESULT {
        ComPtr<ID3D12DescriptorHeap> heap;
        if (FAILED(mDevice->CreateDescriptorHeap(&heapDesc, IID_PPV_ARGS(&heap)))) {
            return E_FAIL;
        }
        *ppPageableOut = heap.Detach();
        return S_OK;
    };

    ComPtr<Heap> descriptorHeap;
    ASSERT_SUCCEEDED(Heap::CreateHeap(descriptorHeapDesc, residencyManager.Get(), createHeapFn,
                                      &descriptorHeap));

    EXPECT_EQ(descriptorHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_STATUS_UNKNOWN);
    EXPECT_EQ(descriptorHeap->GetInfo().IsLocked, false);

    ComPtr<ID3D12DescriptorHeap> heap;
    ASSERT_SUCCEEDED(descriptorHeap.As(&heap));
    EXPECT_NE(heap, nullptr);

    // Residency status of non-resource heap types is unknown, there is no residency usage
    // yet.
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryUsage, 0u);
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryCount, 0u);

    ASSERT_SUCCEEDED(residencyManager->LockHeap(descriptorHeap.Get()));

    EXPECT_EQ(descriptorHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_STATUS_CURRENT_RESIDENT);
    EXPECT_EQ(descriptorHeap->GetInfo().IsLocked, true);

    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryUsage, descriptorHeapDesc.SizeInBytes);
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryCount, 1u);

    ASSERT_SUCCEEDED(residencyManager->UnlockHeap(descriptorHeap.Get()));

    EXPECT_EQ(descriptorHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_STATUS_CURRENT_RESIDENT);
    EXPECT_EQ(descriptorHeap->GetInfo().IsLocked, false);

    // Unlocking a heap does not evict it, the memory usage should not change.
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryUsage, descriptorHeapDesc.SizeInBytes);
    EXPECT_EQ(residencyManager->GetInfo().CurrentMemoryCount, 1u);

    ASSERT_FAILED(residencyManager->UnlockHeap(descriptorHeap.Get()));
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyList) {
    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(CreateBasicAllocatorDesc(),
                                                        &resourceAllocator, nullptr));

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<ResourceAllocation> allocation;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(allocationDesc, CreateBasicBufferDesc(1),
                                                       D3D12_RESOURCE_STATE_COMMON, nullptr,
                                                       &allocation));

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
    // Create residency without adapter must always fail.
    {
        RESIDENCY_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);
        residencyDesc.Adapter = nullptr;

        ASSERT_FAILED(ResidencyManager::CreateResidencyManager(residencyDesc, nullptr));
    }

    // Create residency without device must always fail.
    {
        RESIDENCY_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);
        residencyDesc.Device = nullptr;

        ASSERT_FAILED(ResidencyManager::CreateResidencyManager(residencyDesc, nullptr));
    }

    // Create residency alone.
    {
        ComPtr<ResidencyManager> residencyManager;
        ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(
            CreateBasicResidencyDesc(kDefaultBudget), nullptr));
    }

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

// Keeps allocating until it reaches the restricted budget then over-commits to ensure older heaps
// will evicted.
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

    // Keep allocating until we reach the budget.
    std::vector<ComPtr<ResourceAllocation>> allocationsBelowBudget = {};
    while (resourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize <= kDefaultBudget) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        allocationsBelowBudget.push_back(std::move(allocation));
    }

    // Created allocations below the budget should become resident.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_TRUE(allocation->GetMemory()->IsInResidencyLRUCacheForTesting());
    }

    // Keep allocating |kMemoryOverBudget| over the budget.
    constexpr uint64_t kMemoryOverBudget = GPGMM_MB_TO_BYTES(10);

    // Allocating the same amount over budget, where older allocations will be evicted.
    std::vector<ComPtr<ResourceAllocation>> allocationsAboveBudget = {};
    const uint64_t currentMemoryUsage = resourceAllocator->GetInfo().UsedMemoryUsage;

    while (currentMemoryUsage + kMemoryOverBudget > resourceAllocator->GetInfo().UsedMemoryUsage) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        allocationsAboveBudget.push_back(std::move(allocation));
    }

    // Created allocations above the budget should become resident.
    for (auto& allocation : allocationsAboveBudget) {
        EXPECT_TRUE(allocation->GetMemory()->IsInResidencyLRUCacheForTesting());
    }

    // Created allocations below the budget should NOT become resident.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_FALSE(allocation->GetMemory()->IsInResidencyLRUCacheForTesting());
    }
}

// Keeps allocating until it goes over the OS provided budget.
TEST_F(D3D12ResidencyManagerTests, OverBudgetAsync) {
    constexpr uint64_t kBudgetIsDeterminedByOS = 0;
    RESIDENCY_DESC residencyDesc = CreateBasicResidencyDesc(kBudgetIsDeterminedByOS);
    residencyDesc.Flags ^= RESIDENCY_FLAG_NEVER_UPDATE_BUDGET_ON_WORKER_THREAD;

    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(residencyDesc, &residencyManager));

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
        CreateBasicAllocatorDesc(), residencyManager.Get(), &resourceAllocator));

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    ALLOCATION_DESC bufferAllocationDesc = {};
    bufferAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    D3D12_HEAP_PROPERTIES heapProperties =
        mDevice->GetCustomHeapProperties(0, bufferAllocationDesc.HeapType);

    const DXGI_MEMORY_SEGMENT_GROUP bufferMemorySegment =
        GetMemorySegmentGroup(heapProperties.MemoryPoolPreference, mCaps->IsAdapterUMA());

    const uint64_t memoryUnderBudget = GetBudgetLeft(residencyManager.Get(), bufferMemorySegment);

    // Keep allocating until we reach the budget. Should a budget change occur, we must also
    // terminate the loop since we cannot guarantee all allocations will be created resident.
    std::vector<ComPtr<ResourceAllocation>> allocations = {};
    while (resourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize < memoryUnderBudget &&
           GetBudgetLeft(residencyManager.Get(), bufferMemorySegment) >= kBufferMemorySize) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        allocations.push_back(std::move(allocation));
    }

    // All allocations should become resident.
    for (auto& allocation : allocations) {
        EXPECT_TRUE(allocation->GetMemory()->IsInResidencyLRUCacheForTesting());
    }
}

// Keeps allocating until it reaches the restricted budget then over-commits to ensure new heaps
// will not keep increasing in size.
TEST_F(D3D12ResidencyManagerTests, OverBudgetDisablesGrowth) {
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

    while (resourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize <= kDefaultBudget) {
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

// Keeps allocating until it reaches the restricted budget then over-commits to ensure locked heaps
// will never be evicted.
TEST_F(D3D12ResidencyManagerTests, OverBudgetWithLockedHeaps) {
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

    // Keep allocating until we reach the budget.
    std::vector<ComPtr<ResourceAllocation>> allocationsBelowBudget = {};
    while (resourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize <= kDefaultBudget) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        ASSERT_SUCCEEDED(residencyManager->LockHeap(allocation->GetMemory()));

        allocationsBelowBudget.push_back(std::move(allocation));
    }

    // Locked heaps should stay locked.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().IsLocked, true);
    }

    // Since locked heaps are ineligable for eviction and HEAP_FLAG_ALWAYS_IN_BUDGET is true,
    // CreateResource should always fail since there is not enough budget.
    ASSERT_FAILED(resourceAllocator->CreateResource(bufferAllocationDesc, bufferDesc,
                                                    D3D12_RESOURCE_STATE_COMMON, nullptr, nullptr));

    // Unlocked allocations should be always eligable for eviction.
    for (auto& allocation : allocationsBelowBudget) {
        ASSERT_SUCCEEDED(residencyManager->UnlockHeap(allocation->GetMemory()));
    }

    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
        bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, nullptr));
}

// Creates two sets of heaps, first set is below the budget, second set is above the budget, then
// swaps the residency status using ExecuteCommandList: first set gets paged-in again, second set
// gets paged-out.
TEST_F(D3D12ResidencyManagerTests, ExecuteCommandListOverBudget) {
    ComPtr<ResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(ResidencyManager::CreateResidencyManager(
        CreateBasicResidencyDesc(kDefaultBudget), &residencyManager));

    ComPtr<ResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(ResourceAllocator::CreateAllocator(
        CreateBasicAllocatorDesc(), residencyManager.Get(), &resourceAllocator));

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    // Create the first set of heaps below the budget.
    std::vector<ComPtr<ResourceAllocation>> firstSetOfHeaps = {};
    while (resourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize <= kDefaultBudget) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_STATUS_CURRENT_RESIDENT);
        firstSetOfHeaps.push_back(std::move(allocation));
    }

    // Create the second set of heaps above the budget, the first set will be evicted.
    std::vector<ComPtr<ResourceAllocation>> secondSetOfHeaps = {};
    for (uint64_t i = 0; i < kDefaultBudget / kBufferMemorySize; i++) {
        ComPtr<ResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_STATUS_CURRENT_RESIDENT);
        secondSetOfHeaps.push_back(std::move(allocation));
    }

    // Page-in the first set of heaps using ExecuteCommandLists (and page-out the second set).
    ResidencyList firstSetOfHeapsWorkingSet;
    for (auto& allocation : firstSetOfHeaps) {
        firstSetOfHeapsWorkingSet.Add(allocation->GetMemory());
    }

    ComPtr<ID3D12CommandAllocator> commandAllocator;
    ASSERT_SUCCEEDED(mDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
                                                     IID_PPV_ARGS(&commandAllocator)));

    ComPtr<ID3D12CommandList> commandList;
    ASSERT_SUCCEEDED(mDevice->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT,
                                                commandAllocator.Get(), nullptr,
                                                IID_PPV_ARGS(&commandList)));

    D3D12_COMMAND_QUEUE_DESC queueDesc = {};
    ComPtr<ID3D12CommandQueue> queue;
    ASSERT_SUCCEEDED(mDevice->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&queue)));

    {
        ResidencyList* residencyLists[] = {&firstSetOfHeapsWorkingSet};
        ID3D12CommandList* commandLists[] = {commandList.Get()};
        ASSERT_SUCCEEDED(
            residencyManager->ExecuteCommandLists(queue.Get(), commandLists, residencyLists, 1));
    }

    // Everything below the budget should now be resident.
    for (auto& allocation : firstSetOfHeaps) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_STATUS_CURRENT_RESIDENT);
    }

    // Everything above the budget should now be evicted.
    for (auto& allocation : secondSetOfHeaps) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_STATUS_PENDING_RESIDENCY);
    }

    // Page-in the second set of heaps using ExecuteCommandLists (and page-out the first set).
    ResidencyList secondSetOfHeapsWorkingSet;
    for (auto& allocation : secondSetOfHeaps) {
        secondSetOfHeapsWorkingSet.Add(allocation->GetMemory());
    }

    {
        ResidencyList* residencyLists[] = {&secondSetOfHeapsWorkingSet};
        ID3D12CommandList* commandLists[] = {commandList.Get()};
        ASSERT_SUCCEEDED(
            residencyManager->ExecuteCommandLists(queue.Get(), commandLists, residencyLists, 1));
    }

    // Everything below the budget should now be evicted.
    for (auto& allocation : firstSetOfHeaps) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_STATUS_PENDING_RESIDENCY);
    }

    // Everything above the budget should now be resident.
    for (auto& allocation : secondSetOfHeaps) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_STATUS_CURRENT_RESIDENT);
    }
}