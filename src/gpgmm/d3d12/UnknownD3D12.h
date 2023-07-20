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

#ifndef GPGMM_D3D12_UNKNOWND3D12_H_
#define GPGMM_D3D12_UNKNOWND3D12_H_

#include "gpgmm/d3d12/D3D12Platform.h"
#include "gpgmm/utils/NonCopyable.h"
#include "gpgmm/utils/RefCount.h"

namespace gpgmm::d3d12 {

    /** \brief Unknown is a thread-safe ref-count implementation for custom COM based objects.

    The custom COM based object must override DeleteThis() if they require a custom-deleter.
    */
    class Unknown : public IUnknown, public NonCopyable {
      public:
        Unknown();
        virtual ~Unknown() = default;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

      protected:
        // Derived class may override this if they require a custom deleter.
        virtual void DeleteThis();

      private:
        RefCounted mRefCount;  // Maintains the COM ref-count of this object.
    };

// Helper to provide IUnknown-based object types the required overrides to use Unknown.
#define DEFINE_UNKNOWN_OVERRIDES()                                                            \
    inline HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override { \
        return Unknown::QueryInterface(riid, ppvObject);                                      \
    }                                                                                         \
    inline ULONG STDMETHODCALLTYPE AddRef() override {                                        \
        return Unknown::AddRef();                                                             \
    }                                                                                         \
    inline ULONG STDMETHODCALLTYPE Release() override {                                       \
        return Unknown::Release();                                                            \
    }

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_UNKNOWND3D12_H_
