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

#include "gpgmm/d3d12/UnknownD3D12.h"

namespace gpgmm::d3d12 {
    Unknown::Unknown() : mRefCount(1) {
    }

    HRESULT Unknown::QueryInterface(REFIID riid, void** ppvObject) {
        // Always set out parameter to nullptr, validating it first.
        if (ppvObject == nullptr) {
            return E_INVALIDARG;
        }

        *ppvObject = nullptr;

        if (riid == IID_IUnknown) {
            // Increment reference and return pointer.
            *ppvObject = this;
            mRefCount.Ref();
            return S_OK;
        }

        return E_NOINTERFACE;
    }

    ULONG Unknown::AddRef() {
        mRefCount.Ref();
        return mRefCount.GetRefCount();
    }

    ULONG Unknown::Release() {
        const ULONG refCount = mRefCount.Unref() ? 0 : mRefCount.GetRefCount();
        if (refCount == 0) {
            DeleteThis();
        }
        return refCount;
    }

    void Unknown::DeleteThis() {
        delete this;
    }
}  // namespace gpgmm::d3d12
