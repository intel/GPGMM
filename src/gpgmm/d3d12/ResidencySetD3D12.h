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

namespace gpgmm { namespace d3d12 {

    class Heap;

    /** \brief Represents a set of heaps which are referenced by a command list.

    The set must be updated to ensure each heap is made resident for execution.
    */
    class GPGMM_EXPORT ResidencySet final {
      public:
        /** \brief  Create a residency set or collection of heaps to manage together for residency.
         */
        ResidencySet();
        ~ResidencySet();

        ResidencySet(const ResidencySet&) = default;
        ResidencySet& operator=(const ResidencySet&) = default;

        /** \brief  Insert heap into this residency set.

        @param heap A pointer to Heap about to be inserted.
        \return S_OK if heap was inserted or S_FALSE if heap already exists, else error.
        */
        HRESULT Insert(Heap* heap);

        /** \brief  Reset this residency set.

        Removes all heaps in the set so the set can be re-used.
        */
        HRESULT Reset();

        std::set<Heap*>::iterator begin() const;
        std::set<Heap*>::iterator end() const;

      private:
        const char* GetTypename() const;

        std::set<Heap*> mSet;
    };

}}  // namespace gpgmm::d3d12

#endif
