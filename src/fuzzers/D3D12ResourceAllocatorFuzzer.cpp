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

#include <gpgmm_d3d12.h>

namespace {

    ComPtr<gpgmm::d3d12::ResourceAllocator> gResourceAllocator;

}  // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    gpgmm::d3d12::ALLOCATOR_DESC desc = {};
    gpgmm::d3d12::ResourceAllocator::CreateAllocator(desc, &gResourceAllocator);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8) {
        return 0;
    }

    if (gResourceAllocator == nullptr) {
        return 0;
    }

    D3D12_RESOURCE_DESC resourceDesc = {};
    resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    resourceDesc.Alignment = 0;
    resourceDesc.Width = static_cast<uint64_t>(data[0]);
    resourceDesc.Height = 1;
    resourceDesc.DepthOrArraySize = 1;
    resourceDesc.MipLevels = 1;
    resourceDesc.Format = DXGI_FORMAT_UNKNOWN;
    resourceDesc.SampleDesc.Count = 1;
    resourceDesc.SampleDesc.Quality = 0;
    resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    resourceDesc.Flags = D3D12_RESOURCE_FLAG_NONE;

    gpgmm::d3d12::ALLOCATION_DESC allocationDesc = {};
    allocationDesc.HeapType = D3D12_HEAP_TYPE_DEFAULT;

    ComPtr<gpgmm::d3d12::ResourceAllocation> allocation;
    gResourceAllocator->CreateResource(allocationDesc, resourceDesc, D3D12_RESOURCE_STATE_COMMON,
                                       nullptr, &allocation);
    return 0;
}
