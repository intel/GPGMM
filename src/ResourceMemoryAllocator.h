// Copyright 2019 The Dawn Authors
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

#ifndef GPGMM_RESOURCEMEMORYALLOCATOR_H_
#define GPGMM_RESOURCEMEMORYALLOCATOR_H_

#include "src/ResourceMemoryAllocation.h"

namespace gpgmm {

    // Interface for backend allocators that create memory heaps resoruces can be suballocated in.
    class ResourceMemoryAllocator {
      public:
        virtual ~ResourceMemoryAllocator() = default;

        virtual ResourceMemoryAllocation Allocate(uint64_t size) = 0;
        virtual void Deallocate(ResourceMemoryAllocation& allocation) = 0;
        virtual void Release() = 0;
    };

}  // namespace gpgmm

#endif  // GPGMM_RESOURCEMEMORYALLOCATOR_H_
