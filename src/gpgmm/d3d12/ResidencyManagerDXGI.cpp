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

#include "gpgmm/d3d12/ResidencyManagerDXGI.h"

#include "gpgmm/d3d12/BudgetUpdateDXGI.h"
#include "gpgmm/d3d12/CapsD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"

namespace gpgmm::d3d12 {

    ResidencyManagerDXGI::ResidencyManagerDXGI(const RESIDENCY_MANAGER_DESC& descriptor,
                                               ID3D12Device* pDevice,
                                               IDXGIAdapter3* pAdapter,
                                               std::unique_ptr<Caps> caps)
        : ResidencyManager(descriptor, pDevice, std::move(caps)), mAdapter(pAdapter) {
        ASSERT(mAdapter != nullptr);
    }

    ResidencyManagerDXGI::~ResidencyManagerDXGI() = default;

    HRESULT ResidencyManagerDXGI::QueryMemoryInfoImpl(const RESIDENCY_HEAP_SEGMENT& heapSegment,
                                                      RESIDENCY_MEMORY_INFO* pMemoryInfoOut) {
        // Residency heap segments are 1:1 with DXGI memory segment groups.
        DXGI_QUERY_VIDEO_MEMORY_INFO queryVideoMemoryInfoOut;
        GPGMM_RETURN_IF_FAILED(mAdapter->QueryVideoMemoryInfo(
            0, static_cast<DXGI_MEMORY_SEGMENT_GROUP>(heapSegment), &queryVideoMemoryInfoOut));
        pMemoryInfoOut->AvailableForReservation = queryVideoMemoryInfoOut.AvailableForReservation;
        pMemoryInfoOut->Budget = queryVideoMemoryInfoOut.Budget;
        pMemoryInfoOut->CurrentReservation = queryVideoMemoryInfoOut.CurrentReservation;
        pMemoryInfoOut->CurrentUsage = queryVideoMemoryInfoOut.CurrentUsage;
        return S_OK;
    }

    std::shared_ptr<BudgetUpdateTask> ResidencyManagerDXGI::CreateBudgetUpdateTask() {
        return std::make_shared<BudgetUpdateTaskDXGI>(this);
    }

    IDXGIAdapter3* ResidencyManagerDXGI::GetAdapter() const {
        return mAdapter;
    }

}  // namespace gpgmm::d3d12
