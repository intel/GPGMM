// Copyright 2023 The GPGMM Authors
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

#include "gpgmm/common/TerminationMemoryAllocator.h"

namespace gpgmm {

    ResultOrError<std::unique_ptr<MemoryAllocationBase>>
    TerminationMemoryAllocator::TryAllocateMemory(const MemoryAllocationRequest& request) {
        // Return error because |this| represents the last of the chain of allocators that could
        // process the request.
        return {};
    }

    void TerminationMemoryAllocator::DeallocateMemory(
        std::unique_ptr<MemoryAllocationBase> allocation) {
        // Do nothing because nothing can be allocated.
    }
}  // namespace gpgmm
