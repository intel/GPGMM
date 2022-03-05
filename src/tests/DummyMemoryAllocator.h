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

#ifndef GPGMM_DUMMYMEMORYALLOCATOR_H_
#define GPGMM_DUMMYMEMORYALLOCATOR_H_

#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/common/Utils.h"

namespace gpgmm {

    class DummyMemoryAllocator : public MemoryAllocator {
      public:
        void DeallocateMemory(MemoryAllocation* allocation) override {
            ASSERT(allocation != nullptr);
            ASSERT(allocation->GetMethod() == AllocationMethod::kStandalone);
            mInfo.UsedMemoryCount--;
            mInfo.UsedMemoryUsage -= allocation->GetSize();
            SafeDelete(allocation->GetMemory());
        }

        std::unique_ptr<MemoryAllocation> TryAllocateMemory(uint64_t allocationSize,
                                                            uint64_t alignment,
                                                            bool neverAllocate,
                                                            bool cacheSize) override {
            if (neverAllocate) {
                return {};
            }

            mInfo.UsedMemoryCount++;
            mInfo.UsedMemoryUsage += allocationSize;
            return std::make_unique<MemoryAllocation>(this, new MemoryBase(allocationSize));
        }
    };

}  // namespace gpgmm

#endif  // GPGMM_DUMMYMEMORYALLOCATOR_H_
