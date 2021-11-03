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

#ifndef GPGMM_D3D12_IUNKNOWNIMPLD3D12_H_
#define GPGMM_D3D12_IUNKNOWNIMPLD3D12_H_

#include "src/d3d12/d3d12_platform.h"

#include "../common/RefCount.h"

namespace gpgmm { namespace d3d12 {

    class IUnknownImpl : public IUnknown, public RefCounted {
      public:
        IUnknownImpl() = default;
        virtual ~IUnknownImpl() = default;

        // IUnknown interfaces
        HRESULT QueryInterface(REFIID riid, void** ppvObject) override;
        ULONG AddRef() override;
        ULONG Release() override;

        // Derived class may override this if they require a customer deleter.
        virtual void DeleteThis();
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_IUNKNOWNIMPLD3D12_H_
