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

#include "src/d3d12/FenceD3D12.h"

#include "src/common/Assert.h"

namespace gpgmm { namespace d3d12 {
    Fence::Fence(ComPtr<ID3D12Device> device, uint64_t initialValue)
        : mDevice(device),
          mCompletionEvent(INVALID_HANDLE_VALUE),
          mCurrentFence(-1),
          mLastCompletedFence(-1),
          mLastSignaledFence(-1) {
        mCompletionEvent = CreateEvent(nullptr, false, false, nullptr);
        ASSERT(mCompletionEvent != INVALID_HANDLE_VALUE);

        // TODO: check d3d error
        mDevice->CreateFence(initialValue, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&mFence));

        mLastSignaledFence = GetAndCacheLastCompletedFence();
        mCurrentFence = mLastSignaledFence + 1;
    }

    Fence::~Fence() {
        if (mCompletionEvent != INVALID_HANDLE_VALUE) {
            CloseHandle(mCompletionEvent);
            mCompletionEvent = INVALID_HANDLE_VALUE;
        }
    }

    HRESULT Fence::WaitFor(uint64_t fenceValue) {
        HRESULT hr = S_OK;
        if (!IsCompleted(fenceValue)) {
            hr = mFence->SetEventOnCompletion(fenceValue, mCompletionEvent);

            // Wait for the event to complete (it will automatically reset).
            const uint32_t result = WaitForSingleObject(mCompletionEvent, INFINITE);
            ASSERT(result == 0);

            ASSERT(fenceValue <= mFence->GetCompletedValue());

            // Update the latest completed fence value.
            GetAndCacheLastCompletedFence();
        }
        return hr;
    }

    bool Fence::IsCompleted(uint64_t fenceValue) {
        if (fenceValue <= mLastCompletedFence) {
            return true;
        }
        return fenceValue <= GetAndCacheLastCompletedFence();
    }

    uint64_t Fence::GetAndCacheLastCompletedFence() {
        mLastCompletedFence = mFence->GetCompletedValue();
        return mLastCompletedFence;
    }

    HRESULT Fence::Signal(ID3D12CommandQueue* pCommandQueue) {
        ASSERT(mLastSignaledFence != mCurrentFence);
        HRESULT hr = pCommandQueue->Signal(mFence.Get(), mCurrentFence);
        mLastSignaledFence = mCurrentFence;
        mCurrentFence++;
        return hr;
    }

    uint64_t Fence::GetLastSignaledFence() const {
        return mLastSignaledFence;
    }

    uint64_t Fence::GetCurrentFence() const {
        return mCurrentFence;
    }
}}  // namespace gpgmm::d3d12