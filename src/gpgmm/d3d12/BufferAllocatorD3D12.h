// Copyright 2022 The GPGMM Authors
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

#ifndef SRC_GPGMM_D3D12_BUFFERALLOCATORD3D12_H_
#define SRC_GPGMM_D3D12_BUFFERALLOCATORD3D12_H_

#include "gpgmm/common/MemoryAllocator.h"

#include "gpgmm/d3d12/D3D12Platform.h"

namespace gpgmm::d3d12 {

    class ResourceAllocator;

    class BufferAllocator : public MemoryAllocatorBase {
      public:
        BufferAllocator(ScopedRef<ResourceAllocator> resourceAllocator,
                        D3D12_HEAP_PROPERTIES heapProperties,
                        D3D12_HEAP_FLAGS heapFlags,
                        D3D12_RESOURCE_FLAGS bufferFlags,
                        D3D12_RESOURCE_STATES initialBufferState);
        ~BufferAllocator() override = default;

        // MemoryAllocatorBase interface
        ResultOrError<std::unique_ptr<MemoryAllocationBase>> TryAllocateMemory(
            const MemoryAllocationRequest& request) override;
        void DeallocateMemory(std::unique_ptr<MemoryAllocationBase> allocation) override;

      private:
        const D3D12_HEAP_PROPERTIES mHeapProperties;
        const D3D12_HEAP_FLAGS mHeapFlags;
        const D3D12_RESOURCE_FLAGS mBufferFlags;
        const D3D12_RESOURCE_STATES mInitialBufferState;
    };

}  // namespace gpgmm::d3d12

#endif  // SRC_GPGMM_D3D12_BUFFERALLOCATORD3D12_H_
