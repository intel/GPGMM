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

#include "src/d3d12/ResidencyCacheD3D12.h"
#include "src/d3d12/HeapD3D12.h"

namespace gpgmm { namespace d3d12 {

    bool ResidencyCache::Insert(Heap* heap) {
        if (heap->IsInList()) {
            return false;
        }

        mCache.Append(heap);
        return true;
    }

    Heap* ResidencyCache::GetNext() const {
        if (mCache.empty()) {
            return nullptr;
        }

        return mCache.head()->value();
    }

    void ResidencyCache::Remove(Heap* heap) {
        heap->RemoveFromList();
    }

}}  // namespace gpgmm::d3d12
