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

#include "gpgmm/d3d12/FenceD3D12.h"

#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/utils/Assert.h"

namespace gpgmm::d3d12 {

    // static
    HRESULT Fence::CreateFence(ID3D12Device* device, uint64_t initialValue, Fence** fenceOut) {
        ComPtr<ID3D12Fence> fence;
        GPGMM_RETURN_IF_FAILED(
            device->CreateFence(initialValue, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence)));
        *fenceOut = new Fence(fence, initialValue);
        return S_OK;
    }

    Fence::Fence(ComPtr<ID3D12Fence> fence, uint64_t initialValue)
        : mFence(fence),
          mCompletionEvent(INVALID_HANDLE_VALUE),
          mCurrentFence(-1),
          mLastCompletedFence(-1),
          mLastSignaledFence(-1) {
        ASSERT(mFence != nullptr);

        mCompletionEvent = CreateEvent(nullptr, false, false, nullptr);
        ASSERT(mCompletionEvent != INVALID_HANDLE_VALUE);

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
        if (!IsCompleted(fenceValue)) {
            GPGMM_RETURN_IF_FAILED(mFence->SetEventOnCompletion(fenceValue, mCompletionEvent));

            // Wait for the event to complete (it will automatically reset).
            const uint32_t result = WaitForSingleObject(mCompletionEvent, INFINITE);
            ASSERT(result == 0);

            ASSERT(fenceValue <= mFence->GetCompletedValue());

            // Update the latest completed fence value.
            GetAndCacheLastCompletedFence();
        }
        return S_OK;
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
        GPGMM_RETURN_IF_FAILED(pCommandQueue->Signal(mFence.Get(), mCurrentFence));
        mLastSignaledFence = mCurrentFence;
        mCurrentFence++;
        return S_OK;
    }

    uint64_t Fence::GetLastSignaledFence() const {
        return mLastSignaledFence;
    }

    uint64_t Fence::GetCurrentFence() const {
        return mCurrentFence;
    }

    ID3D12Fence* Fence::GetFence() const {
        return mFence.Get();
    }

}  // namespace gpgmm::d3d12
