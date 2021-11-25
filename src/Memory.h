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

#ifndef GPGMM_MEMORY_H_
#define GPGMM_MEMORY_H_

#include "common/NonCopyable.h"
#include "common/RefCount.h"

namespace gpgmm {

    class MemoryPool;

    // Represents a allocated memory block or heap.
    // When memory is sub-allocated it will have a non-zero refcount.
    class MemoryBase : public RefCounted, public NonCopyable {
      public:
        MemoryBase(uint64_t size);
        virtual ~MemoryBase();

        // Return the size of the memory block or heap.
        uint64_t GetSize() const;

        // Get the memory pool of the memory block or heap.
        // When memory gets de-allocated, it will be returned to this pool.
        MemoryPool* GetPool() const;
        void SetPool(MemoryPool* pool);

      private:
        const uint64_t mSize;
        MemoryPool* mPool = nullptr;
    };

}  // namespace gpgmm

#endif  // GPGMM_MEMORY_H_
