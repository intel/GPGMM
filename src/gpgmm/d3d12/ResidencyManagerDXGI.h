// Copyright 2024 The GPGMM Authors
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

#ifndef SRC_GPGMM_D3D12_RESIDENCYMANAGERDXGI_H_
#define SRC_GPGMM_D3D12_RESIDENCYMANAGERDXGI_H_

#include "gpgmm/d3d12/ResidencyManagerD3D12.h"

#include <dxgi1_4.h>

namespace gpgmm::d3d12 {

    // Implements residency management for DXGI 1.4 and newer adapters.
    class ResidencyManagerDXGI final : public ResidencyManager {
      public:
        ResidencyManagerDXGI(const RESIDENCY_MANAGER_DESC& descriptor,
                             ID3D12Device* pDevice,
                             IDXGIAdapter3* pAdapter,
                             std::unique_ptr<Caps> caps);

        ~ResidencyManagerDXGI() override;

        IDXGIAdapter3* GetAdapter() const;

      private:
        // ResidencyManager overloads
        HRESULT QueryMemoryInfoImpl(const RESIDENCY_HEAP_SEGMENT& heapSegment,
                                    RESIDENCY_MEMORY_INFO* pMemoryInfoOut) override;

        std::shared_ptr<BudgetUpdateTask> CreateBudgetUpdateTask() override;

        IDXGIAdapter3* mAdapter = nullptr;
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_RESIDENCYMANAGERDXGI_H_
