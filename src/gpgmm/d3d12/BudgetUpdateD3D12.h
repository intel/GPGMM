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

#ifndef SRC_GPGMM_D3D12_BUDGETUPDATED3D12_H_
#define SRC_GPGMM_D3D12_BUDGETUPDATED3D12_H_

#include "gpgmm/common/ThreadPool.h"
#include "gpgmm/d3d12/D3D12Platform.h"

#include <memory>
#include <mutex>

namespace gpgmm::d3d12 {

    // Creates a long-lived task to recieve and process OS budget change events.
    class BudgetUpdateTask : public VoidCallback {
      public:
        BudgetUpdateTask();
        ~BudgetUpdateTask() override;

        // Shutdown the event loop.
        virtual bool UnregisterAndExit() = 0;

        virtual HRESULT GetLastError() const;

      protected:
        void SetLastError(HRESULT hr);

        mutable std::mutex mMutex;  // Protect access between threads for members below.
        HRESULT mLastError = S_OK;
    };

    class BudgetUpdateEvent final : public Event {
      public:
        BudgetUpdateEvent(std::shared_ptr<Event> event, std::shared_ptr<BudgetUpdateTask> task);

        // Event overrides
        void Wait() override;
        bool IsSignaled() override;
        void Signal() override;

        bool UnregisterAndExit();

        HRESULT GetLastError() const;

      private:
        std::shared_ptr<BudgetUpdateTask> mTask;
        std::shared_ptr<Event> mEvent;
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_BUDGETUPDATED3D12_H_
