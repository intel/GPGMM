// Copyright 2019 The Dawn Authors
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

#ifndef GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
#define GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_

#include "src/ResourceMemoryAllocation.h"
#include "src/d3d12/d3d12_platform.h"

namespace gpgmm { namespace d3d12 {

    class Heap;
    class ResourceAllocator;
    class ResidencySet;

    class ResourceAllocation : public ResourceMemoryAllocation, public IUnknown {
      public:
        ResourceAllocation() = default;
        ResourceAllocation(ResourceAllocator* allocator,
                           const AllocationInfo& info,
                           uint64_t offset,
                           ComPtr<ID3D12Resource> resource,
                           Heap* heap);
        ~ResourceAllocation() override = default;
        ResourceAllocation(const ResourceAllocation&) = default;
        ResourceAllocation& operator=(const ResourceAllocation&) = default;

        // IUnknown interfaces
        HRESULT QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG AddRef() override;
        ULONG Release() override;

        HRESULT Map(uint32_t subresource, const D3D12_RANGE* pRange, void** ppMappedData);
        void Unmap(uint32_t subresource, const D3D12_RANGE* pRange);

        ID3D12Resource* GetResource() const;
        HRESULT SetDebugName(const char* name);

        void UpdateResidency(ResidencySet* residencySet);
        bool IsResidentForTesting() const;

      protected:
        void ReleaseThis();

      private:
        ComPtr<ID3D12Resource> mResource;
        uint32_t mRefCount = 1;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATIOND3D12_H_
