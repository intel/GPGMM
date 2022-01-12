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

#ifndef GPGMM_D3D12_RESIDENCYSETD3D12_H_
#define GPGMM_D3D12_RESIDENCYSETD3D12_H_

#include "gpgmm/d3d12/d3d12_platform.h"
#include "include/gpgmm_export.h"

#include <set>
#include <vector>

namespace gpgmm { namespace d3d12 {

    class Heap;
    class ResidencyManager;

    // Represents a set of resource allocations which are referenced by a command list.
    // The set must be updated to ensure each allocations is resident for execution.
    class GPGMM_EXPORT ResidencySet {
      public:
        ResidencySet() = default;
        ~ResidencySet() = default;

        HRESULT Insert(Heap* heap);
        HRESULT Reset();

      private:
        friend ResidencyManager;

        std::set<Heap*> mSet;
        std::vector<Heap*> mToMakeResident;
    };

}}  // namespace gpgmm::d3d12

#endif
