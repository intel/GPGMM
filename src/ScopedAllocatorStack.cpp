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

#include "src/ScopedAllocatorStack.h"

namespace gpgmm {

    MemoryAllocator* ScopedAllocatorStack::GetAllocator() const {
        return mAllocators.back().get();
    }

    MemoryAllocator* ScopedAllocatorStack::PushAllocator(
        std::unique_ptr<MemoryAllocator> allocator) {
        mAllocators.push_back(std::move(allocator));
        return mAllocators.back().get();
    }

}  // namespace gpgmm