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

#ifndef GPGMM_SCOPED_ALLOCATOR_STACK_H_
#define GPGMM_SCOPED_ALLOCATOR_STACK_H_

#include "src/MemoryAllocator.h"

#include <vector>

namespace gpgmm {

    // Scopes memory allocators together in the order they are
    // dependent on each other where only the last allocator is used.
    class ScopedAllocatorStack {
      public:
        ScopedAllocatorStack() = default;
        ~ScopedAllocatorStack() = default;

        MemoryAllocator* GetAllocator() const;
        MemoryAllocator* PushAllocator(std::unique_ptr<MemoryAllocator> allocator);

      private:
        std::vector<std::unique_ptr<MemoryAllocator>> mAllocators;
    };

}  // namespace gpgmm

#endif  // GPGMM_SCOPED_ALLOCATOR_STACK_H_
