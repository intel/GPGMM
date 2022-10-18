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

#ifndef GPGMM_D3D12_RESIDENCYLISTD3D12_H_
#define GPGMM_D3D12_RESIDENCYLISTD3D12_H_

#include "gpgmm/d3d12/IUnknownImplD3D12.h"
#include "gpgmm/d3d12/d3d12_platform.h"

#include <gpgmm_d3d12.h>

#include <vector>

namespace gpgmm::d3d12 {

    class Heap;
    class JSONSerializer;
    class ResidencyManager;

    class ResidencyList final : public IResidencyList, public IUnknownImpl {
      public:
        ResidencyList();
        ~ResidencyList() override;

        HRESULT Add(IHeap* pHeap) override;
        HRESULT Reset() override;

        DEFINE_IUNKNOWNIMPL_OVERRIDES()

      private:
        friend JSONSerializer;
        friend ResidencyManager;

        using UnderlyingType = std::vector<Heap*>;

        UnderlyingType::const_iterator begin() const;
        UnderlyingType::const_iterator end() const;

        const char* GetTypename() const;

        UnderlyingType mList;
    };

}  // namespace gpgmm::d3d12

#endif
