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

#include "src/ResourceMemoryAllocation.h"
#include "src/ResourceMemory.h"
#include "src/common/Assert.h"

namespace gpgmm {

    ResourceMemoryAllocation::ResourceMemoryAllocation()
        : mAllocator(nullptr), mOffset(0), mResourceMemory(nullptr), mMappedPointer(nullptr) {
    }

    ResourceMemoryAllocation::ResourceMemoryAllocation(ResourceAllocatorBase* allocator,
                                                       const AllocationInfo& info,
                                                       uint64_t offset,
                                                       ResourceMemoryBase* resourceMemory,
                                                       uint8_t* mappedPointer)
        : mAllocator(allocator),
          mInfo(info),
          mOffset(offset),
          mResourceMemory(resourceMemory),
          mMappedPointer(mappedPointer) {
    }

    ResourceMemoryBase* ResourceMemoryAllocation::GetResourceMemory() const {
        return mResourceMemory;
    }

    uint64_t ResourceMemoryAllocation::GetOffset() const {
        ASSERT(mInfo.mMethod != AllocationMethod::kInvalid);
        return mOffset;
    }

    AllocationInfo ResourceMemoryAllocation::GetInfo() const {
        return mInfo;
    }

    uint8_t* ResourceMemoryAllocation::GetMappedPointer() const {
        return mMappedPointer;
    }

    void ResourceMemoryAllocation::Invalidate() {
        mResourceMemory = nullptr;
        mInfo = {};
    }

    ResourceAllocatorBase* ResourceMemoryAllocation::GetAllocator() {
        return mAllocator;
    }
}  // namespace gpgmm
