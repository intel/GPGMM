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

#include "gpgmm/d3d12/BudgetUpdateDXGI.h"

#include "gpgmm/common/Message.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/LogD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerDXGI.h"

namespace gpgmm::d3d12 {

    BudgetUpdateTaskDXGI::BudgetUpdateTaskDXGI(ResidencyManagerDXGI* const residencyManager)
        : mResidencyManager(residencyManager),
          mBudgetNotificationUpdateEvent(CreateEventW(NULL, FALSE, FALSE, NULL)),
          mUnregisterAndExitEvent(CreateEventW(NULL, FALSE, FALSE, NULL)) {
        ASSERT(mResidencyManager != nullptr);
        mLastError =
            mResidencyManager->GetAdapter()->RegisterVideoMemoryBudgetChangeNotificationEvent(
                mBudgetNotificationUpdateEvent, &mCookie);
    }

    BudgetUpdateTaskDXGI::~BudgetUpdateTaskDXGI() {
        CloseHandle(mUnregisterAndExitEvent);
        CloseHandle(mBudgetNotificationUpdateEvent);
    }

    MaybeError BudgetUpdateTaskDXGI::operator()() {
        HRESULT hr = GetLastError();
        bool isExiting = false;
        while (!isExiting && SUCCEEDED(hr)) {
            // Wait on two events: one to unblock for OS budget changes, and another to unblock
            // for shutdown.
            HANDLE hWaitEvents[2] = {mBudgetNotificationUpdateEvent, mUnregisterAndExitEvent};
            const DWORD waitedEvent =
                WaitForMultipleObjects(2, hWaitEvents, /*bWaitAll*/ false, INFINITE);
            switch (waitedEvent) {
                // mBudgetNotificationUpdateEvent
                case (WAIT_OBJECT_0 + 0): {
                    hr = mResidencyManager->UpdateMemorySegments();
                    if (FAILED(hr)) {
                        break;
                    }

                    DebugLog(MessageId::kBudgetUpdated, mResidencyManager)
                        << "Updated budget from OS notification.";
                    break;
                }
                // mUnregisterAndExitEvent
                case (WAIT_OBJECT_0 + 1): {
                    isExiting = true;
                    break;
                }
                default: {
                    UNREACHABLE();
                    break;
                }
            }
        }

        if (FAILED(hr)) {
            ErrorLog(ErrorCode::kBudgetInvalid, mResidencyManager)
                << "Unable to update budget: " +
                       GetErrorResultMessage(hr, mResidencyManager->GetDevice());
        }

        SetLastError(hr);
        return GetErrorCode(hr);
    }

    bool BudgetUpdateTaskDXGI::UnregisterAndExit() {
        mResidencyManager->GetAdapter()->UnregisterVideoMemoryBudgetChangeNotification(mCookie);
        return SetEvent(mUnregisterAndExitEvent);
    }

}  // namespace gpgmm::d3d12
