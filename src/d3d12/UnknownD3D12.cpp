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

#include "src/d3d12/UnknownD3D12.h"

namespace gpgmm { namespace d3d12 {
    HRESULT Unknown::QueryInterface(REFIID riid, void** ppvObject) {
        // Always set out parameter to nullptr, validating it first.
        if (ppvObject == nullptr) {
            return E_INVALIDARG;
        }

        *ppvObject = nullptr;

        if (riid == IID_IUnknown) {
            // Increment reference and return pointer.
            *ppvObject = this;
            ++mRefCount;
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG Unknown::AddRef() {
        return ++mRefCount;
    }

    ULONG Unknown::Release() {
        const uint32_t refcount = --mRefCount;
        if (mRefCount == 0) {
            ReleaseThis();
        }
        return refcount;
    }

    void Unknown::ReleaseThis() {
        delete this;
    }
}}  // namespace gpgmm::d3d12