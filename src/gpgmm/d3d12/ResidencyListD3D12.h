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

#ifndef GPGMM_D3D12_RESIDENCYLISTD3D12_H_
#define GPGMM_D3D12_RESIDENCYLISTD3D12_H_

#include "gpgmm/d3d12/d3d12_platform.h"
#include "include/gpgmm_export.h"

#include <vector>

namespace gpgmm::d3d12 {

    class Heap;

    /** \brief Represents a list of heaps which will be "made resident" when executing a
    command-list.

    A residency list helps track heaps for residency which will be referenced together by a
    command-list. The application uses a ResidencyList by inserting heaps, by calling
    ResourceAllocation::GetMemory, into the list. Once ResidencyManager::ExecuteCommandLists is
    called, the list can be reset or cleared for the next frame.

    Without a ResidencyList, the application would need to manually ResidencyManager::LockHeap and
    ResidencyManager::UnlockHeap each heap before and after ResidencyManager::ExecuteCommandLists,
    respectively.
    */
    class GPGMM_EXPORT ResidencyList final {
      public:
        /** \brief  Create a residency list or collection of heaps to manage together for residency.
         */
        ResidencyList();
        ~ResidencyList();

        ResidencyList(const ResidencyList&) = default;
        ResidencyList& operator=(const ResidencyList&) = default;

        /** \brief  Adds a heap to the residency list.

        @param pHeap A pointer to Heap about to be added.

        \return S_OK if heap was added, else error.
        */
        HRESULT Add(Heap* pHeap);

        /** \brief  Reset this residency list.

        Removes all heaps from the list so the list can be re-used.
        */
        HRESULT Reset();

        using UnderlyingType = std::vector<Heap*>;

        UnderlyingType::const_iterator begin() const;
        UnderlyingType::const_iterator end() const;

      private:
        const char* GetTypename() const;

        UnderlyingType mList;
    };

}  // namespace gpgmm::d3d12

#endif
