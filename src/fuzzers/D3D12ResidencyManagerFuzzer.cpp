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

#include <vector>

#include "testing/libfuzzer/libfuzzer_exports.h"

#include "D3D12Fuzzer.h"
#include "gpgmm/common/SizeClass.h"

namespace {

    ComPtr<gpgmm::d3d12::ResourceAllocator> gResourceAllocator;
    ComPtr<gpgmm::d3d12::ResidencyManager> gResidencyManager;
    std::vector<ComPtr<gpgmm::d3d12::ResourceAllocation>> gAllocationsBelowBudget = {};

    uint64_t GetBudgetLeft(gpgmm::d3d12::ResidencyManager* const residencyManager,
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
    if (FAILED(CreateAllocatorDesc(&allocatorDesc))) {
        return 0;
    }

    allocatorDesc.Flags |= gpgmm::d3d12::ALLOCATOR_FLAG_ALWAYS_IN_BUDGET;

    gpgmm::d3d12::RESIDENCY_DESC residencyDesc = {};

    ComPtr<IDXGIAdapter3> adapter3;
    if (FAILED(allocatorDesc.Adapter.As(&adapter3))) {
        return 0;
    }

    residencyDesc.Adapter = adapter3;
    residencyDesc.Device = allocatorDesc.Device;
    residencyDesc.MinLogLevel = D3D12_MESSAGE_SEVERITY_MESSAGE;

    // Create ResidencyManager
    D3D12_FEATURE_DATA_ARCHITECTURE arch = {};
    if (FAILED(residencyDesc.Device->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE, &arch,
                                                         sizeof(arch)))) {
        return 0;
    }

    residencyDesc.IsUMA = arch.UMA;

    if (FAILED(gpgmm::d3d12::ResidencyManager::CreateResidencyManager(residencyDesc,
                                                                      &gResidencyManager))) {
        return 0;
    }

    if (FAILED(gpgmm::d3d12::ResourceAllocator::CreateAllocator(
            allocatorDesc, gResidencyManager.Get(), &gResourceAllocator))) {
        return 0;
    }

    gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    const DXGI_MEMORY_SEGMENT_GROUP bufferMemorySegment =
        gResidencyManager->GetMemorySegmentGroup(allocationDesc.HeapType);

    constexpr uint64_t kBufferMemorySize = GPGMM_MB_TO_BYTES(1);
    const D3D12_RESOURCE_DESC bufferDesc = CreateBufferDesc(kBufferMemorySize);

    // Keep allocating until we reach the budget.
    uint64_t memoryUnderBudget = GetBudgetLeft(gResidencyManager.Get(), bufferMemorySegment);
    while (gResourceAllocator->GetInfo().UsedMemoryUsage + kBufferMemorySize < memoryUnderBudget) {
        ComPtr<gpgmm::d3d12::ResourceAllocation> allocation;
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

    ComPtr<gpgmm::d3d12::ResourceAllocation> allocationOverBudget;
    gResourceAllocator->CreateResource(allocationDesc, CreateBufferDesc(UInt8ToUInt64(data)),
                                       D3D12_RESOURCE_STATE_COMMON, nullptr, &allocationOverBudget);
    return 0;
}
