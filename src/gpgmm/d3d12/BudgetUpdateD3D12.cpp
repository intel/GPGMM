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

#include "gpgmm/d3d12/BudgetUpdateD3D12.h"

namespace gpgmm::d3d12 {

    // BudgetUpdateTask

    BudgetUpdateTask::BudgetUpdateTask() = default;

    BudgetUpdateTask::~BudgetUpdateTask() = default;

    HRESULT BudgetUpdateTask::GetLastError() const {
        std::lock_guard<std::mutex> lock(mMutex);
        return mLastError;
    }

    void BudgetUpdateTask::SetLastError(HRESULT hr) {
        std::lock_guard<std::mutex> lock(mMutex);
        mLastError = hr;
    }

    // BudgetUpdateEvent

    BudgetUpdateEvent::BudgetUpdateEvent(std::shared_ptr<Event> event,
                                         std::shared_ptr<BudgetUpdateTask> task)
        : mTask(task), mEvent(event) {
    }

    void BudgetUpdateEvent::Wait() {
        mEvent->Wait();
    }

    bool BudgetUpdateEvent::IsSignaled() {
        return mEvent->IsSignaled();
    }

    void BudgetUpdateEvent::Signal() {
        return mEvent->Signal();
    }

    bool BudgetUpdateEvent::UnregisterAndExit() {
        return mTask->UnregisterAndExit();
    }

    bool BudgetUpdateEvent::GetLastError() const {
        return mTask->GetLastError();
    }

}  // namespace gpgmm::d3d12
