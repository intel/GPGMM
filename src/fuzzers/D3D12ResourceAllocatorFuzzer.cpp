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

#include <cstdint>

#include "testing/libfuzzer/libfuzzer_exports.h"

#include "D3D12Fuzzer.h"

namespace {

    ComPtr<gpgmm::d3d12::ResourceAllocator> gResourceAllocator;

}  // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    gpgmm::d3d12::ALLOCATOR_DESC allocatorDesc = {};
    if (FAILED(CreateAllocatorDesc(&allocatorDesc))) {
        return 0;
    }

    if (FAILED(
            gpgmm::d3d12::ResourceAllocator::CreateAllocator(allocatorDesc, &gResourceAllocator))) {
        return 0;
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8) {
        return 0;
    }

    gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<gpgmm::d3d12::ResourceAllocation> allocation;
    gResourceAllocator->CreateResource(allocationDesc, CreateBufferDesc(UInt8ToUInt64(data)),
                                       D3D12_RESOURCE_STATE_COMMON, nullptr, &allocation);
    return 0;
}
