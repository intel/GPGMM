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

#ifndef GPGMM_D3D12_IUNKNOWNIMPLD3D12_H_
#define GPGMM_D3D12_IUNKNOWNIMPLD3D12_H_

#include "gpgmm/d3d12/d3d12_platform.h"
#include "gpgmm/utils/NonCopyable.h"
#include "include/gpgmm_export.h"

#ifndef GPGMM_REFCOUNT_TYPE
#    include "gpgmm/utils/RefCount.h"
/** \brief Defines the atomic-type to use for ref-counting the COM object.
    \param type
*/ 
#    define GPGMM_REFCOUNT_TYPE RefCounted
#endif

namespace gpgmm::d3d12 {

    /** \brief IUnknownImpl is a thread-safe ref-count implementation for custom COM based objects.

    The custom COM based object must override DeleteThis() if they require a custom-deleter.
    */
    class GPGMM_EXPORT IUnknownImpl : public IUnknown, public NonCopyable {
      public:
        IUnknownImpl();
        virtual ~IUnknownImpl() = default;

        // IUnknown interface
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG STDMETHODCALLTYPE AddRef() override;
        ULONG STDMETHODCALLTYPE Release() override;

      protected:
        // Derived class may override this if they require a custom deleter.
        virtual void DeleteThis();

      private:
        GPGMM_REFCOUNT_TYPE mRefCount;  // Maintains the COM ref-count of this object.
    };

}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_IUNKNOWNIMPLD3D12_H_
