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

#include "gpgmm/d3d12/DebugObjectD3D12.h"

namespace gpgmm { namespace d3d12 {

    std::string DebugObject::GetDebugName() const {
        return mDebugName;
    }

    HRESULT DebugObject::SetDebugName(const std::string& name) {
        mDebugName = name;
        return SetDebugNameImpl(name);
    }

}}  // namespace gpgmm::d3d12
