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
#ifndef GPGMM_D3D12_UTILSD3D12_H_
#define GPGMM_D3D12_UTILSD3D12_H_

#include "src/MemoryAllocator.h"
#include "src/d3d12/d3d12_platform.h"

#define ReturnIfFailed(expr) \
    {                        \
        HRESULT hr = expr;   \
        if (FAILED(hr)) {    \
            return hr;       \
        }                    \
    }                        \
    for (;;)                 \
    break

#define ReturnIfSucceeded(expr) \
    {                           \
        HRESULT hr = expr;      \
        if (SUCCEEDED(hr)) {    \
            return hr;          \
        }                       \
    }                           \
    for (;;)                    \
    break

namespace gpgmm { namespace d3d12 {

    // Combines AllocatorMemory and Create*Resource into a single call.
    // If the memory allocation was successful, the resource will be created using it.
    // Else, if the resource creation fails, the memory allocation will be cleaned up.
    template <typename CreateResourceFn>
    HRESULT TryAllocateResource(MemoryAllocator* allocator,
                                uint64_t size,
                                uint64_t alignment,
                                bool neverAllocate,
                                CreateResourceFn&& createResourceFn) {
        std::unique_ptr<MemoryAllocation> allocation =
            allocator->TryAllocateMemory(size, alignment, neverAllocate);
        if (allocation == nullptr) {
            return E_FAIL;
        }
        HRESULT hr = createResourceFn(*allocation);
        if (FAILED(hr)) {
            allocator->DeallocateMemory(allocation.release());
        }
        return hr;
    }

    bool IsDepthFormat(DXGI_FORMAT format);

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_UTILSD3D12_H_
