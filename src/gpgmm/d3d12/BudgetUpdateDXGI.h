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

#ifndef SRC_GPGMM_D3D12_BUDGETUPDATEDXGI_H_
#define SRC_GPGMM_D3D12_BUDGETUPDATEDXGI_H_

#include "gpgmm/d3d12/BudgetUpdateD3D12.h"

namespace gpgmm::d3d12 {

    class ResidencyManagerDXGI;

    // Implements a long running task that can continuously receives DXGI budget notifications.
    class BudgetUpdateTaskDXGI final : public BudgetUpdateTask {
      public:
        BudgetUpdateTaskDXGI(ResidencyManagerDXGI* const residencyManager);
        ~BudgetUpdateTaskDXGI() override;

      private:
        // VoidCallback interface
        MaybeError operator()() override;

        // BudgetUpdateTask interface
        bool UnregisterAndExit() override;

        ResidencyManagerDXGI* const mResidencyManager;

        HANDLE mBudgetNotificationUpdateEvent = INVALID_HANDLE_VALUE;
        HANDLE mUnregisterAndExitEvent = INVALID_HANDLE_VALUE;

        DWORD mCookie = 0;  // Used to unregister from notifications.
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_BUDGETUPDATEDXGI_H_
