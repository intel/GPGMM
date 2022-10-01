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

#include "gpgmm/d3d12/ResidencyListD3D12.h"

#include "gpgmm/common/TraceEvent.h"

namespace gpgmm::d3d12 {

    HRESULT CreateResidencyList(IResidencyList** ppResidencyList) {
        if (ppResidencyList != nullptr) {
            *ppResidencyList = new ResidencyList();
        }
        return S_OK;
    }

    ResidencyList::ResidencyList() {
        GPGMM_TRACE_EVENT_OBJECT_NEW(this);
    }

    ResidencyList::~ResidencyList() {
        GPGMM_TRACE_EVENT_OBJECT_DESTROY(this);
    }

    HRESULT ResidencyList::Add(IHeap* pHeap) {
        if (pHeap == nullptr) {
            return E_INVALIDARG;
        }

        mList.push_back(pHeap);
        return S_OK;
    }

    HRESULT ResidencyList::Reset() {
        mList.clear();
        return S_OK;
    }

    ResidencyList::UnderlyingType::const_iterator ResidencyList::begin() const {
        return mList.begin();
    }

    ResidencyList::UnderlyingType::const_iterator ResidencyList::end() const {
        return mList.end();
    }

    const char* ResidencyList::GetTypename() const {
        return "ResidencyList";
    }

}  // namespace gpgmm::d3d12
