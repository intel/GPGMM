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

#ifndef GPGMM_D3D12_FENCED3D12_H_
#define GPGMM_D3D12_FENCED3D12_H_

#include "src/d3d12/d3d12_platform.h"

#include <cstdint>

namespace gpgmm { namespace d3d12 {

    class Fence {
      public:
        Fence(ComPtr<ID3D12Device> device, uint64_t initialValue);
        ~Fence();

        HRESULT WaitFor(uint64_t fenceValue);
        HRESULT Signal(ID3D12CommandQueue* pCommandQueue);

        uint64_t GetLastSignaledFence() const;
        uint64_t GetCurrentFence() const;

      private:
        bool IsCompleted(uint64_t fenceValue);
        uint64_t GetAndCacheLastCompletedFence();

        ComPtr<ID3D12Device> mDevice;
        ComPtr<ID3D12Fence> mFence;

        HANDLE mCompletionEvent;
        uint64_t mCurrentFence;
        uint64_t mLastCompletedFence;
        uint64_t mLastSignaledFence;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_FENCED3D12_H_
