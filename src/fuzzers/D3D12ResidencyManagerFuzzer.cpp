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

#include <vector>

#include "testing/libfuzzer/libfuzzer_exports.h"

#include "D3D12Fuzzer.h"
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/d3d12/UtilsD3D12.h"

namespace {

    ComPtr<gpgmm::d3d12::IResourceAllocator> gResourceAllocator;
    ComPtr<gpgmm::d3d12::IResidencyManager> gResidencyManager;
    std::vector<ComPtr<gpgmm::d3d12::IResourceAllocation>> gAllocationsBelowBudget = {};

    uint64_t GetBudgetLeft(gpgmm::d3d12::IResidencyManager* const residencyManager,
                           const DXGI_MEMORY_SEGMENT_GROUP& memorySegmentGroup) {
        if (residencyManager == nullptr) {
            return 0;
        }
        DXGI_QUERY_VIDEO_MEMORY_INFO segment = {};
        gResidencyManager->QueryVideoMemoryInfo(memorySegmentGroup, &segment);
        return (segment.Budget > segment.CurrentUsage) ? (segment.Budget - segment.CurrentUsage)
                                                       : 0;
    }

}  // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    gpgmm::d3d12::ALLOCATOR_DESC allocatorDesc = {};
    if (FAILED(CreateResourceAllocatorDesc(&allocatorDesc))) {
        return 0;
    }

    allocatorDesc.Flags |= gpgmm::d3d12::ALLOCATOR_FLAG_ALWAYS_IN_BUDGET;

    gpgmm::d3d12::RESIDENCY_DESC residencyDesc = {};

    ComPtr<IDXGIAdapter3> adapter3;
    ComPtr<IDXGIAdapter> adapter(allocatorDesc.Adapter);
    if (FAILED(adapter.As(&adapter3))) {
        return 0;
    }

    residencyDesc.Adapter = adapter3.Get();
    residencyDesc.Device = allocatorDesc.Device;
    residencyDesc.MinLogLevel = D3D12_MESSAGE_SEVERITY_MESSAGE;

    // Create ResidencyManager
    D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
    if (FAILED(residencyDesc.Device->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch,
                                                         sizeof(arch)))) {
        return 0;
    }

    residencyDesc.IsUMA = arch.UMA;

    if (FAILED(gpgmm::d3d12::CreateResidencyManager(residencyDesc, &gResidencyManager))) {
        return 0;
    }

    if (FAILED(gpgmm::d3d12::CreateResourceAllocator(allocatorDesc, gResidencyManager.Get(),
                                                     &gResourceAllocator))) {
        return 0;
    }

    gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    D3D12_HEAP_PROPERTIES heapProperties =
        residencyDesc.Device->GetCustomHeapProperties(0, allocationDesc.HeapType);

    const DXGI_MEMORY_SEGMENT_GROUP bufferMemorySegment = gpgmm::d3d12::GetMemorySegmentGroup(
        heapProperties.MemoryPoolPreference, residencyDesc.IsUMA);

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBufferDesc(kBufferMemorySize);

    // Keep allocating until we reach the budget.
    uint64_t memoryUnderBudget = GetBudgetLeft(gResidencyManager.Get(), bufferMemorySegment);
    while (gResourceAllocator->GetStats().UsedMemoryUsage + kBufferMemorySize < memoryUnderBudget) {
        ComPtr<gpgmm::d3d12::IResourceAllocation> allocation;
        if (FAILED(gResourceAllocator->CreateResource({}, bufferDesc, D3D12_RESOURCE_STATE_COMMON,
                                                      nullptr, &allocation))) {
            return 0;
        }

        gAllocationsBelowBudget.push_back(std::move(allocation));
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8) {
        return 0;
    }

    gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<gpgmm::d3d12::IResourceAllocation> allocationOverBudget;
    gResourceAllocator->CreateResource(allocationDesc, CreateBufferDesc(UInt8ToUInt64(data)),
                                       D3D12_RESOURCE_STATE_COMMON, nullptr, &allocationOverBudget);
    return 0;
}
