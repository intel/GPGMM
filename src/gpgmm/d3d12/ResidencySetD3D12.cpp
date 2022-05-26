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

#include "gpgmm/d3d12/ResidencySetD3D12.h"

#include "gpgmm/common/Debug.h"

namespace gpgmm { namespace d3d12 {

    ResidencySet::ResidencySet() {
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);
    }

    ResidencySet::~ResidencySet() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
    }

    HRESULT ResidencySet::Insert(Heap* heap) {
        if (heap == nullptr) {
            return E_INVALIDARG;
        }
        if (mSet.insert(heap).second) {
            return S_OK;
        }
        return S_FALSE;
    }

    HRESULT ResidencySet::Reset() {
        mSet.clear();
        return S_OK;
    }

    std::set<Heap*>::iterator ResidencySet::begin() const {
        return mSet.begin();
    }

    std::set<Heap*>::iterator ResidencySet::end() const {
        return mSet.end();
    }

    const char* ResidencySet::GetTypename() const {
        return "ResidencySet";
    }

}}  // namespace gpgmm::d3d12
