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

#include "gpgmm/d3d12/DebugObjectD3D12.h"

#include "gpgmm/utils/WindowsUtils.h"

namespace gpgmm::d3d12 {

    LPCWSTR DebugObject::GetDebugName() const {
        return mDebugName.c_str();
    }

    HRESULT DebugObject::SetDebugName(LPCWSTR Name) {
        if (Name == nullptr) {
            return S_FALSE;
        }
        // Store a copy of the name because D3D12 oddly doesn't have a ID3D12Object::GetName.
        mDebugName = TCharToWString(Name);
        return SetDebugNameImpl(Name);
    }

}  // namespace gpgmm::d3d12
