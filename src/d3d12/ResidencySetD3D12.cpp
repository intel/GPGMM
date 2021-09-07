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

#include "src/d3d12/ResidencySetD3D12.h"

#include "src/common/Assert.h"

namespace gpgmm { namespace d3d12 {
    void ResidencySet::Insert(Heap* heap) {
        ASSERT(heap != nullptr);
        bool inserted = mSet.insert(heap).second;
        if (inserted) {
            mToMakeResident.push_back(heap);
        }
    }

    void ResidencySet::Reset() {
        mSet.clear();
        mToMakeResident.clear();
    }
}}  // namespace gpgmm::d3d12