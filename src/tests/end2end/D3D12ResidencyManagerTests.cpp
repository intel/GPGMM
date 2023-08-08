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
#include "gpgmm/d3d12/ResourceHeapAllocatorD3D12.h"
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
    RESOURCE_ALLOCATOR_DESC CreateBasicAllocatorDesc() const {
        RESOURCE_ALLOCATOR_DESC desc = D3D12TestBase::CreateBasicAllocatorDesc();


        // Require MakeResident/Evict occur near CreateResource, for debugging purposes.
        desc.Flags |= gpgmm::d3d12::RESOURCE_ALLOCATOR_FLAG_ALWAYS_IN_BUDGET;

        // Disable memory growth so older heap being paged out are the same size as newer heaps
        // being paged-in, and the test expectation based on these sizes is easy to determine.
        desc.ResourceHeapGrowthFactor = 1.0f;

        return desc;
    }

    // Configures residency manager for testing residency in a controlled and predictable
    // fashion.
    RESIDENCY_MANAGER_DESC CreateBasicResidencyDesc(uint64_t budget) const {
        RESIDENCY_MANAGER_DESC residencyDesc = D3D12TestBase::CreateBasicResidencyDesc();

        // Specify a restricted budget, the OS budget fluctuates unpredicatbly.
        residencyDesc.MaxBudgetInBytes = budget;

        return residencyDesc;
    }

    uint64_t GetBudgetLeft(IResidencyManager* residencyManager,
                           const DXGI_MEMORY_SEGMENT_GROUP& heapSegment) {
        DXGI_QUERY_VIDEO_MEMORY_INFO segment = {};
        residencyManager->QueryVideoMemoryInfo(heapSegment, &segment);
        return (segment.Budget > segment.CurrentUsage) ? (segment.Budget - segment.CurrentUsage)
                                                       : 0;
    }

    DXGI_MEMORY_SEGMENT_GROUP GetHeapSegment(D3D12_HEAP_TYPE heapType) const {
        D3D12_HEAP_PROPERTIES heapProperties = mDevice->GetCustomHeapProperties(0, heapType);
        return ::GetHeapSegment(heapProperties.MemoryPoolPreference, mCaps->IsAdapterUMA());
    }

    bool IsResident(IResourceAllocation* pAllocation) const {
        ASSERT(pAllocation != nullptr);
        return pAllocation->GetMemory()->GetInfo().Status == RESIDENCY_HEAP_STATUS_CURRENT;
    }

    class CreateDescHeapCallbackContext {
      public:
        CreateDescHeapCallbackContext(ID3D12Device* device, D3D12_DESCRIPTOR_HEAP_DESC descHeapDesc)
            : mDevice(device), mDescHeapDesc(descHeapDesc) {
        }
        static HRESULT CreateResidencyHeap(void* pContext, ID3D12Pageable** ppPageableOut) {
            CreateDescHeapCallbackContext* createDescHeapCallbackContext =
                static_cast<CreateDescHeapCallbackContext*>(pContext);
            return createDescHeapCallbackContext->CreateResidencyHeap(ppPageableOut);
        }

      private:
        HRESULT CreateResidencyHeap(ID3D12Pageable** ppPageableOut) {
            ComPtr<ID3D12DescriptorHeap> heap;
            if (FAILED(mDevice->CreateDescriptorHeap(&mDescHeapDesc, IID_PPV_ARGS(&heap)))) {
                return E_FAIL;
            }
            *ppPageableOut = heap.Detach();
            return S_OK;
        }
        ID3D12Device* mDevice;
        D3D12_DESCRIPTOR_HEAP_DESC mDescHeapDesc;
    };

    class BadCreateHeapCallbackContext {
      public:
        BadCreateHeapCallbackContext() {
        }
        static HRESULT CreateHeap(void* pContext, ID3D12Pageable** ppPageableOut) {
            BadCreateHeapCallbackContext* badCreateHeapCallbackContext =
                static_cast<BadCreateHeapCallbackContext*>(pContext);
            return badCreateHeapCallbackContext->CreateHeap(ppPageableOut);
        }

      private:
        HRESULT CreateHeap(ID3D12Pageable** ppPageableOut) {
            return S_OK;
        }
    };
};

TEST_F(D3D12ResidencyManagerTests, CreateResourceHeapNotResident) {
    // Adapters that do not support creating heaps will ignore D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT.
    GPGMM_SKIP_TEST_IF(!mCaps->IsCreateHeapNotResidentSupported());

    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget), mDevice.Get(),
                                            mAdapter.Get(), &residencyManager));

    constexpr uint64_t kHeapSize = GPGMM_MB_TO_BYTES(10);

    D3D12_HEAP_PROPERTIES heapProperties = {};
    heapProperties.Type = D3D12_HEAP_TYPE_DEFAULT;

    RESIDENCY_HEAP_DESC resourceHeapInBudgetDesc = {};
    resourceHeapInBudgetDesc.SizeInBytes = kHeapSize;
    resourceHeapInBudgetDesc.HeapSegment = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;
    resourceHeapInBudgetDesc.Flags |= RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET;

    D3D12_HEAP_DESC heapDesc = {};
    heapDesc.Properties = heapProperties;
    heapDesc.SizeInBytes = kHeapSize;
    heapDesc.Flags |= D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS;
    heapDesc.Flags |= D3D12_HEAP_FLAG_CREATE_NOT_RESIDENT;

    CreateResourceHeapCallbackContext createHeapContext(mDevice.Get(), &heapDesc);

    ASSERT_SUCCEEDED(CreateResidencyHeap(resourceHeapInBudgetDesc, residencyManager.Get(),
                                         CreateResourceHeapCallbackContext::CreateHeap,
                                         &createHeapContext, nullptr));
}

TEST_F(D3D12ResidencyManagerTests, CreateResourceHeap) {
    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget), mDevice.Get(),
                                            mAdapter.Get(), &residencyManager));

    constexpr uint64_t kHeapSize = GPGMM_MB_TO_BYTES(10);

    D3D12_HEAP_PROPERTIES heapProperties = {};
    heapProperties.Type = D3D12_HEAP_TYPE_DEFAULT;

    D3D12_HEAP_DESC heapDesc = {};
    heapDesc.Properties = heapProperties;
    heapDesc.SizeInBytes = kHeapSize;

    // Assume tier 1, which all adapters support.
    heapDesc.Flags |= D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS;

    CreateResourceHeapCallbackContext createHeapContext(mDevice.Get(), &heapDesc);
    BadCreateHeapCallbackContext badCreateHeapCallbackContext;

    RESIDENCY_HEAP_DESC residencyHeapDesc = {};
    residencyHeapDesc.SizeInBytes = kHeapSize;
    residencyHeapDesc.HeapSegment = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;

    ASSERT_FAILED(CreateResidencyHeap(residencyHeapDesc, residencyManager.Get(),
                                      BadCreateHeapCallbackContext::CreateHeap,
                                      &badCreateHeapCallbackContext, nullptr));

    ASSERT_SUCCEEDED(CreateResidencyHeap(residencyHeapDesc, residencyManager.Get(),
                                         CreateResourceHeapCallbackContext::CreateHeap,
                                         &createHeapContext, nullptr));

    // Create a resource heap by importing the heap.
    {
        ComPtr<ID3D12Pageable> pageable;
        CreateResourceHeapCallbackContext::CreateHeap(&createHeapContext, &pageable);
        ASSERT_SUCCEEDED(CreateResidencyHeap(residencyHeapDesc, nullptr, pageable.Get(), nullptr));
    }

    // Create a resource heap without residency.
    ComPtr<IResidencyHeap> resourceHeap;
    ASSERT_SUCCEEDED(CreateResidencyHeap(residencyHeapDesc, nullptr,
                                         CreateResourceHeapCallbackContext::CreateHeap,
                                         &createHeapContext, &resourceHeap));

    {
        RESIDENCY_HEAP_DESC invalidResidencyHeapDesc = residencyHeapDesc;
        invalidResidencyHeapDesc.Flags |= RESIDENCY_HEAP_FLAG_CREATE_RESIDENT;

        ASSERT_FAILED(CreateResidencyHeap(invalidResidencyHeapDesc, nullptr,
                                          CreateResourceHeapCallbackContext::CreateHeap,
                                          &createHeapContext, nullptr));
    }

    {
        RESIDENCY_HEAP_DESC invalidResidencyHeapDesc = residencyHeapDesc;
        invalidResidencyHeapDesc.Flags |= RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET;

        ASSERT_FAILED(CreateResidencyHeap(invalidResidencyHeapDesc, nullptr,
                                          CreateResourceHeapCallbackContext::CreateHeap,
                                          &createHeapContext, nullptr));
    }

    // Ensure the unmanaged resource heap state is always unknown. Even though D3D12 implicitly
    // creates heaps as resident, untrack resource heaps would never transition out from
    // RESIDENCY_HEAP_STATUS_CURRENT and must be left RESIDENCY_HEAP_STATUS_UNKNOWN.
    EXPECT_EQ(resourceHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_HEAP_STATUS_UNKNOWN);
    EXPECT_EQ(resourceHeap->GetInfo().IsLocked, false);

    // Create a resource heap with residency.
    ASSERT_SUCCEEDED(CreateResidencyHeap(residencyHeapDesc, residencyManager.Get(),
                                         CreateResourceHeapCallbackContext::CreateHeap,
                                         &createHeapContext, &resourceHeap));
    ASSERT_NE(resourceHeap, nullptr);

    EXPECT_EQ(resourceHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_HEAP_STATUS_CURRENT);
    EXPECT_EQ(resourceHeap->GetInfo().IsLocked, false);

    // Residency status of resource heap types is always known.
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapUsage, residencyHeapDesc.SizeInBytes);
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapCount, 1u);

    ComPtr<ID3D12Heap> heap;
    ASSERT_SUCCEEDED(resourceHeap.As(&heap));
    EXPECT_NE(heap, nullptr);

    ASSERT_SUCCEEDED(residencyManager->LockHeap(resourceHeap.Get()));

    EXPECT_EQ(resourceHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_HEAP_STATUS_CURRENT);
    EXPECT_EQ(resourceHeap->GetInfo().IsLocked, true);

    EXPECT_EQ(GetStats(residencyManager).CurrentHeapUsage, residencyHeapDesc.SizeInBytes);
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapCount, 1u);

    ASSERT_SUCCEEDED(residencyManager->UnlockHeap(resourceHeap.Get()));

    EXPECT_EQ(resourceHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_HEAP_STATUS_CURRENT);
    EXPECT_EQ(resourceHeap->GetInfo().IsLocked, false);

    // Unlocking a heap does not evict it, the memory usage should not change.
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapUsage, residencyHeapDesc.SizeInBytes);
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapCount, 1u);

    ASSERT_SUCCEEDED(residencyManager->UnlockHeap(resourceHeap.Get()));  // Not locked
}

TEST_F(D3D12ResidencyManagerTests, CreateDescriptorHeap) {
    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget), mDevice.Get(),
                                            mAdapter.Get(), &residencyManager));

    D3D12_DESCRIPTOR_HEAP_DESC heapDesc = {};
    heapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    heapDesc.NumDescriptors = 1;
    heapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;

    RESIDENCY_HEAP_DESC descriptorHeapDesc = {};
    descriptorHeapDesc.SizeInBytes =
        heapDesc.NumDescriptors * mDevice->GetDescriptorHandleIncrementSize(heapDesc.Type);
    descriptorHeapDesc.HeapSegment = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;

    CreateDescHeapCallbackContext createDescHeapCallbackContext(mDevice.Get(), heapDesc);

    ComPtr<IResidencyHeap> descriptorHeap;
    ASSERT_SUCCEEDED(CreateResidencyHeap(descriptorHeapDesc, residencyManager.Get(),
                                         CreateDescHeapCallbackContext::CreateResidencyHeap,
                                         &createDescHeapCallbackContext, &descriptorHeap));

    EXPECT_EQ(descriptorHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_HEAP_STATUS_UNKNOWN);
    EXPECT_EQ(descriptorHeap->GetInfo().IsLocked, false);

    ComPtr<ID3D12DescriptorHeap> heap;
    ASSERT_SUCCEEDED(descriptorHeap.As(&heap));
    EXPECT_NE(heap, nullptr);

    // Residency status of non-resource heap types is unknown, there is no residency usage
    // yet.
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapUsage, 0u);
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapCount, 0u);

    ASSERT_SUCCEEDED(residencyManager->LockHeap(descriptorHeap.Get()));

    EXPECT_EQ(descriptorHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_HEAP_STATUS_CURRENT);
    EXPECT_EQ(descriptorHeap->GetInfo().IsLocked, true);

    EXPECT_EQ(GetStats(residencyManager).CurrentHeapUsage, descriptorHeapDesc.SizeInBytes);
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapCount, 1u);

    ASSERT_SUCCEEDED(residencyManager->UnlockHeap(descriptorHeap.Get()));

    EXPECT_EQ(descriptorHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_HEAP_STATUS_CURRENT);
    EXPECT_EQ(descriptorHeap->GetInfo().IsLocked, false);

    // Unlocking a heap does not evict it, the memory usage should not change.
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapUsage, descriptorHeapDesc.SizeInBytes);
    EXPECT_EQ(GetStats(residencyManager).CurrentHeapCount, 1u);

    ASSERT_SUCCEEDED(residencyManager->UnlockHeap(descriptorHeap.Get()));
}

TEST_F(D3D12ResidencyManagerTests, CreateDescriptorHeapResident) {
    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget), mDevice.Get(),
                                            mAdapter.Get(), &residencyManager));

    D3D12_DESCRIPTOR_HEAP_DESC heapDesc = {};
    heapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    heapDesc.NumDescriptors = 1;
    heapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;

    RESIDENCY_HEAP_DESC descriptorHeapDesc = {};
    descriptorHeapDesc.SizeInBytes =
        heapDesc.NumDescriptors * mDevice->GetDescriptorHandleIncrementSize(heapDesc.Type);
    descriptorHeapDesc.HeapSegment = DXGI_MEMORY_SEGMENT_GROUP_LOCAL;
    descriptorHeapDesc.Flags |= RESIDENCY_HEAP_FLAG_CREATE_RESIDENT;

    CreateDescHeapCallbackContext createDescHeapCallbackContext(mDevice.Get(), heapDesc);

    ComPtr<IResidencyHeap> descriptorHeap;
    ASSERT_SUCCEEDED(CreateResidencyHeap(descriptorHeapDesc, residencyManager.Get(),
                                         CreateDescHeapCallbackContext::CreateResidencyHeap,
                                         &createDescHeapCallbackContext, &descriptorHeap));

    EXPECT_EQ(descriptorHeap->GetInfo().Status, gpgmm::d3d12::RESIDENCY_HEAP_STATUS_CURRENT);
    EXPECT_EQ(descriptorHeap->GetInfo().IsLocked, false);
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyList) {
    ComPtr<IResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                             mAdapter.Get(), &resourceAllocator, nullptr));

    ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<IResourceAllocation> allocation;
    ASSERT_SUCCEEDED(resourceAllocator->CreateResource(allocationDesc, CreateBasicBufferDesc(1),
                                                       D3D12_RESOURCE_STATE_COMMON, nullptr,
                                                       &allocation));

    // Inserting a non-existant heap should always fail
    {
        ComPtr<IResidencyList> list;
        ASSERT_SUCCEEDED(CreateResidencyList(&list));
        IResidencyHeap* invalid = nullptr;
        ASSERT_FAILED(list->Add(invalid));
    }

    // Inserting from a valid allocation should always succeed.
    {
        ComPtr<IResidencyList> list;
        ASSERT_SUCCEEDED(CreateResidencyList(&list));

        ASSERT_SUCCEEDED(list->Add(allocation->GetMemory()));
        ASSERT_SUCCEEDED(list->Add(allocation->GetMemory()));
    }

    // Re-inserting allocation between two sets should always succeed.
    {
        ComPtr<IResidencyList> listA;
        ASSERT_SUCCEEDED(CreateResidencyList(&listA));

        ASSERT_SUCCEEDED(listA->Add(allocation->GetMemory()));

        ComPtr<IResidencyList> listB;
        ASSERT_SUCCEEDED(CreateResidencyList(&listB));

        EXPECT_EQ(listB->Add(allocation->GetMemory()), S_OK);
    }
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyManager) {
    // Create residency without adapter must always fail.
    {
        ASSERT_FAILED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget),
                                             mDevice.Get(), nullptr, nullptr));
    }

    // Create residency without device must always fail.
    {
        ASSERT_FAILED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget), nullptr,
                                             mAdapter.Get(), nullptr));
    }

    // Create residency alone.
    {
        ComPtr<IResidencyManager> residencyManager;
        ASSERT_SUCCEEDED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget),
                                                mDevice.Get(), mAdapter.Get(), nullptr));
    }

    // Create allocator with residency support, together.
    {
        ComPtr<IResidencyManager> residencyManager;
        ComPtr<IResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                                 mAdapter.Get(), &resourceAllocator,
                                                 &residencyManager));
        EXPECT_NE(resourceAllocator, nullptr);
        EXPECT_NE(residencyManager, nullptr);
    }

    // Create allocator with residency, seperately, but no adapter should fail.
    {
        RESOURCE_ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();

        ComPtr<IResidencyManager> residencyManager;
        ComPtr<IResourceAllocator> resourceAllocator;
        ASSERT_FAILED(CreateResourceAllocator(allocatorDesc, mDevice.Get(), nullptr,
                                              &resourceAllocator, &residencyManager));
    }

    // Create allocator with residency, seperately.
    {
        ComPtr<IResidencyManager> residencyManager;
        ASSERT_SUCCEEDED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget),
                                                mDevice.Get(), mAdapter.Get(), &residencyManager));

        ComPtr<IResourceAllocator> resourceAllocator;
        ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                                 mAdapter.Get(), residencyManager.Get(),
                                                 &resourceAllocator));
        EXPECT_NE(resourceAllocator, nullptr);
        EXPECT_NE(residencyManager, nullptr);
    }
}

// Verify the residency manager will not increment the device refcount upon creation.
TEST_F(D3D12ResidencyManagerTests, CreateResidencyManagerWithoutDeviceAddRef) {
    const uint32_t beforeDeviceRefCount = GetRefCount(mDevice.Get());

    // Create a residency manager without adding a ref to the device.
    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget), mDevice.Get(),
                                            mAdapter.Get(), &residencyManager));

    const uint32_t afterDeviceRefCount = GetRefCount(mDevice.Get());

    EXPECT_EQ(beforeDeviceRefCount, afterDeviceRefCount);
}

TEST_F(D3D12ResidencyManagerTests, CreateResidencyManagerNoLeak) {
    GPGMM_TEST_MEMORY_LEAK_START();

    // Create allocator with residency support, together.
    {
        ComPtr<IResidencyManager> residencyManager;
        ComPtr<IResourceAllocator> resourceAllocator;
        CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(), mAdapter.Get(),
                                &resourceAllocator, &residencyManager);
    }

    // Create allocator with residency, seperately.
    {
        ComPtr<IResidencyManager> residencyManager;
        CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget), mDevice.Get(),
                               mAdapter.Get(), &residencyManager);

        ComPtr<IResourceAllocator> resourceAllocator;
        CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(), mAdapter.Get(),
                                residencyManager.Get(), &resourceAllocator);
    }

    GPGMM_TEST_MEMORY_LEAK_END();
}

// Keeps allocating until it reaches the restricted budget then over-commits to ensure older heaps
// will evicted.
TEST_F(D3D12ResidencyManagerTests, OverBudget) {
    RESIDENCY_MANAGER_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);

    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(
        CreateResidencyManager(residencyDesc, mDevice.Get(), mAdapter.Get(), &residencyManager));

    ComPtr<IResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                             mAdapter.Get(), residencyManager.Get(),
                                             &resourceAllocator));

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    ALLOCATION_DESC bufferAllocationDesc = {};
    bufferAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    // Keep allocating until we reach the budget.
    std::vector<ComPtr<IResourceAllocation>> allocationsBelowBudget = {};
    while (GetStats(resourceAllocator).UsedHeapUsage + kBufferMemorySize <= kDefaultBudget) {
        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        allocationsBelowBudget.push_back(std::move(allocation));
    }

    // Created allocations below the budget should become resident.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_TRUE(IsResident(allocation.Get()));
    }

    // Keep allocating |kMemoryOverBudget| over the budget.
    constexpr uint64_t kMemoryOverBudget = GPGMM_MB_TO_BYTES(10);

    // Allocating the same amount over budget, where older allocations will be evicted.
    std::vector<ComPtr<IResourceAllocation>> allocationsAboveBudget = {};
    const uint64_t CurrentHeapUsage = GetStats(resourceAllocator).UsedHeapUsage;

    while (CurrentHeapUsage + kMemoryOverBudget > GetStats(resourceAllocator).UsedHeapUsage) {
        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        allocationsAboveBudget.push_back(std::move(allocation));
    }

    // Budget updates are not occuring frequently enough to detect going over budget will evict the
    // same amount.
    if (GetBudgetLeft(residencyManager.Get(), GetHeapSegment(bufferAllocationDesc.HeapType)) > 0) {
        return;
    }

    // Created allocations above the budget should become resident.
    for (auto& allocation : allocationsAboveBudget) {
        EXPECT_TRUE(IsResident(allocation.Get()));
    }

    // Created allocations below the budget should NOT become resident.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_FALSE(IsResident(allocation.Get()));
    }
}

// Keeps allocating until it goes over the OS provided budget.
TEST_F(D3D12ResidencyManagerTests, OverBudgetAsync) {
    constexpr uint64_t kBudgetIsDeterminedByOS = 0;
    RESIDENCY_MANAGER_DESC residencyDesc = CreateBasicResidencyDesc(kBudgetIsDeterminedByOS);
    residencyDesc.Flags |= RESIDENCY_MANAGER_FLAG_ALLOW_BACKGROUND_BUDGET_UPDATES;

    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(
        CreateResidencyManager(residencyDesc, mDevice.Get(), mAdapter.Get(), &residencyManager));

    ComPtr<IResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                             mAdapter.Get(), residencyManager.Get(),
                                             &resourceAllocator));

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    ALLOCATION_DESC bufferAllocationDesc = {};
    bufferAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    const DXGI_MEMORY_SEGMENT_GROUP bufferMemorySegment =
        GetHeapSegment(bufferAllocationDesc.HeapType);

    const uint64_t memoryUnderBudget = GetBudgetLeft(residencyManager.Get(), bufferMemorySegment);

    // Keep allocating until we reach the budget. Should a budget change occur, we must also
    // terminate the loop since we cannot guarantee all allocations will be created resident.
    std::vector<ComPtr<IResourceAllocation>> allocations = {};
    while (GetStats(resourceAllocator).UsedHeapUsage + kBufferMemorySize < memoryUnderBudget &&
           GetBudgetLeft(residencyManager.Get(), bufferMemorySegment) >= kBufferMemorySize) {
        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        allocations.push_back(std::move(allocation));
    }

    // All allocations should become resident.
    for (auto& allocation : allocations) {
        EXPECT_TRUE(IsResident(allocation.Get()));
    }
}

// Keeps allocating until it reaches the restricted budget then over-commits to ensure new heaps
// will not keep increasing in size.
TEST_F(D3D12ResidencyManagerTests, OverBudgetDisablesGrowth) {
    RESIDENCY_MANAGER_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);

    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(
        CreateResidencyManager(residencyDesc, mDevice.Get(), mAdapter.Get(), &residencyManager));

    RESOURCE_ALLOCATOR_DESC allocatorDesc = CreateBasicAllocatorDesc();
    allocatorDesc.ResourceHeapGrowthFactor = 2.0f;

    ComPtr<IResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                             mAdapter.Get(), residencyManager.Get(),
                                             &resourceAllocator));

    std::vector<ComPtr<IResourceAllocation>> allocations = {};
    std::vector<IResidencyHeap*> resourceHeaps = {};

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    ALLOCATION_DESC bufferAllocationDesc = {};
    bufferAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    while (GetStats(resourceAllocator).UsedHeapUsage + kBufferMemorySize <= kDefaultBudget) {
        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        resourceHeaps.push_back(allocation->GetMemory());
        allocations.push_back(std::move(allocation));
    }

    // Check growth occured
    for (size_t heapIndex = 1; heapIndex < resourceHeaps.size(); heapIndex++) {
        EXPECT_LE(resourceHeaps[heapIndex - 1]->GetInfo().SizeInBytes,
                  resourceHeaps[heapIndex]->GetInfo().SizeInBytes);
    }

    // With no budget left, the last resource heap size should not increase.
    ASSERT_GT(resourceHeaps.size(), 1u);
    EXPECT_LE(resourceHeaps.at(allocations.size() - 1)->GetInfo().SizeInBytes,
              resourceHeaps.at(allocations.size() - 2)->GetInfo().SizeInBytes);
}

// Keeps allocating until it reaches the restricted budget then over-commits to ensure locked heaps
// will never be evicted.
TEST_F(D3D12ResidencyManagerTests, OverBudgetWithLockedHeaps) {
    RESIDENCY_MANAGER_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);

    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(
        CreateResidencyManager(residencyDesc, mDevice.Get(), mAdapter.Get(), &residencyManager));

    ComPtr<IResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                             mAdapter.Get(), residencyManager.Get(),
                                             &resourceAllocator));

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    ALLOCATION_DESC bufferAllocationDesc = {};
    bufferAllocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    // Keep allocating until we reach the budget.
    std::vector<ComPtr<IResourceAllocation>> allocationsBelowBudget = {};
    while (GetStats(resourceAllocator).UsedHeapUsage + kBufferMemorySize <= kDefaultBudget) {
        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            bufferAllocationDesc, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));

        ASSERT_SUCCEEDED(residencyManager->LockHeap(allocation->GetMemory()));

        allocationsBelowBudget.push_back(std::move(allocation));
    }

    // Locked heaps should stay locked.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().IsLocked, true);
    }

    // Budget updates are not occuring frequently enough to detect going over budget will evict the
    // same amount.
    if (GetBudgetLeft(residencyManager.Get(), GetHeapSegment(bufferAllocationDesc.HeapType)) > 0) {
        return;
    }

    // Since locked heaps are ineligable for eviction and RESIDENCY_HEAP_FLAG_CREATE_IN_BUDGET is
    // true, CreateResource should always fail since there is not enough budget.
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
TEST_F(D3D12ResidencyManagerTests, OverBudgetExecuteCommandList) {
    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(CreateResidencyManager(CreateBasicResidencyDesc(kDefaultBudget), mDevice.Get(),
                                            mAdapter.Get(), &residencyManager));

    ComPtr<IResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                             mAdapter.Get(), residencyManager.Get(),
                                             &resourceAllocator));

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    // Create the first set of heaps below the budget.
    std::vector<ComPtr<IResourceAllocation>> firstSetOfHeaps = {};
    while (GetStats(resourceAllocator).UsedHeapUsage + kBufferMemorySize <= kDefaultBudget) {
        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_HEAP_STATUS_CURRENT);
        firstSetOfHeaps.push_back(std::move(allocation));
    }

    // Create the second set of heaps above the budget, the first set will be evicted.
    std::vector<ComPtr<IResourceAllocation>> secondSetOfHeaps = {};
    for (uint64_t i = 0; i < kDefaultBudget / kBufferMemorySize; i++) {
        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_HEAP_STATUS_CURRENT);
        secondSetOfHeaps.push_back(std::move(allocation));
    }

    // Budget updates are not occuring frequently enough to detect going over budget will evict the
    // same amount.
    if (GetBudgetLeft(residencyManager.Get(), GetHeapSegment(D3D12_HEAP_TYPE_DEFAULT)) > 0) {
        return;
    }

    // Page-in the first set of heaps using ExecuteCommandLists (and page-out the second set).
    ComPtr<IResidencyList> firstSetOfHeapsWorkingSet;
    ASSERT_SUCCEEDED(CreateResidencyList(&firstSetOfHeapsWorkingSet));

    for (auto& allocation : firstSetOfHeaps) {
        firstSetOfHeapsWorkingSet->Add(allocation->GetMemory());
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
        IResidencyList* residencyLists[] = {firstSetOfHeapsWorkingSet.Get()};
        ID3D12CommandList* commandLists[] = {commandList.Get()};
        ASSERT_SUCCEEDED(
            residencyManager->ExecuteCommandLists(queue.Get(), commandLists, residencyLists, 1));
    }

    // Everything below the budget should now be resident.
    for (auto& allocation : firstSetOfHeaps) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_HEAP_STATUS_CURRENT);
    }

    // Everything above the budget should now be evicted.
    for (auto& allocation : secondSetOfHeaps) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_HEAP_STATUS_PENDING);
    }

    // Page-in the second set of heaps using ExecuteCommandLists (and page-out the first set).
    ComPtr<IResidencyList> secondSetOfHeapsWorkingSet;
    ASSERT_SUCCEEDED(CreateResidencyList(&secondSetOfHeapsWorkingSet));

    for (auto& allocation : secondSetOfHeaps) {
        secondSetOfHeapsWorkingSet->Add(allocation->GetMemory());
    }

    {
        IResidencyList* residencyLists[] = {secondSetOfHeapsWorkingSet.Get()};
        ID3D12CommandList* commandLists[] = {commandList.Get()};
        ASSERT_SUCCEEDED(
            residencyManager->ExecuteCommandLists(queue.Get(), commandLists, residencyLists, 1));
    }

    // Everything below the budget should now be evicted.
    for (auto& allocation : firstSetOfHeaps) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_HEAP_STATUS_PENDING);
    }

    // Everything above the budget should now be resident.
    for (auto& allocation : secondSetOfHeaps) {
        EXPECT_EQ(allocation->GetMemory()->GetInfo().Status, RESIDENCY_HEAP_STATUS_CURRENT);
    }
}

TEST_F(D3D12ResidencyManagerTests, OverBudgetImported) {
    RESIDENCY_MANAGER_DESC residencyDesc = CreateBasicResidencyDesc(kDefaultBudget);

    ComPtr<IResidencyManager> residencyManager;
    ASSERT_SUCCEEDED(
        CreateResidencyManager(residencyDesc, mDevice.Get(), mAdapter.Get(), &residencyManager));

    ComPtr<IResourceAllocator> resourceAllocator;
    ASSERT_SUCCEEDED(CreateResourceAllocator(CreateBasicAllocatorDesc(), mDevice.Get(),
                                             mAdapter.Get(), residencyManager.Get(),
                                             &resourceAllocator));

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBasicBufferDesc(kBufferMemorySize);

    // Keep importing externally allocated resources until we reach the budget.
    std::vector<ComPtr<IResourceAllocation>> allocationsBelowBudget = {};
    while (GetStats(resourceAllocator).UsedHeapUsage + kBufferMemorySize <= kDefaultBudget) {
        D3D12_HEAP_PROPERTIES heapProperties = {};
        heapProperties.Type = D3D12_HEAP_TYPE_DEFAULT;

        ComPtr<ID3D12Resource> resource;
        ASSERT_SUCCEEDED(mDevice->CreateCommittedResource(&heapProperties, D3D12_HEAP_FLAG_NONE,
                                                          &bufferDesc, D3D12_RESOURCE_STATE_COMMON,
                                                          nullptr, IID_PPV_ARGS(&resource)));

        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(
            resourceAllocator->CreateResource({}, resource.Get(), &allocation));  // import
        allocationsBelowBudget.push_back(std::move(allocation));
    }

    // Created allocations below the budget should become resident.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_TRUE(IsResident(allocation.Get()));
    }

    // Keep allocating |kMemoryOverBudget| over the budget.
    constexpr uint64_t kMemoryOverBudget = GPGMM_MB_TO_BYTES(10);

    // Allocating the same amount over budget, where older allocations will be evicted.
    std::vector<ComPtr<IResourceAllocation>> allocationsAboveBudget = {};
    const uint64_t CurrentHeapUsage = GetStats(resourceAllocator).UsedHeapUsage;

    while (CurrentHeapUsage + kMemoryOverBudget > GetStats(resourceAllocator).UsedHeapUsage) {
        ComPtr<IResourceAllocation> allocation;
        ASSERT_SUCCEEDED(resourceAllocator->CreateResource(
            {}, bufferDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation));
        allocationsAboveBudget.push_back(std::move(allocation));
    }

    // Created allocations above the budget should become resident.
    for (auto& allocation : allocationsAboveBudget) {
        EXPECT_TRUE(IsResident(allocation.Get()));
    }

    // Budget updates are not occuring frequently enough to detect going over budget will evict the
    // same amount.
    if (GetBudgetLeft(residencyManager.Get(), GetHeapSegment(D3D12_HEAP_TYPE_DEFAULT)) > 0) {
        return;
    }

    // Created allocations below the budget should NOT become resident.
    for (auto& allocation : allocationsBelowBudget) {
        EXPECT_FALSE(IsResident(allocation.Get()));
    }
}
