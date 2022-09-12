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

#include "gpgmm/d3d12/DebugResourceAllocatorD3D12.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/JSONSerializerD3D12.h"
#include "gpgmm/d3d12/ResourceAllocationD3D12.h"
#include "gpgmm/utils/Utils.h"

namespace gpgmm::d3d12 {

    DebugResourceAllocator::ResourceAllocationEntry::ResourceAllocationEntry(
        ResourceAllocation* allocation)
        : mAllocation(allocation) {
    }

    DebugResourceAllocator::ResourceAllocationEntry::ResourceAllocationEntry(
        ResourceAllocation* allocation,
        MemoryAllocator* allocator)
        : mAllocation(allocation), mAllocator(allocator) {
    }

    MemoryAllocator* DebugResourceAllocator::ResourceAllocationEntry::GetAllocator() const {
        return mAllocator;
    }

    ResourceAllocation* DebugResourceAllocator::ResourceAllocationEntry::GetAllocation() const {
        return mAllocation;
    }

    size_t DebugResourceAllocator::ResourceAllocationEntry::GetKey() const {
        return reinterpret_cast<uintptr_t>(mAllocation);
    }

    void DebugResourceAllocator::ReportLiveAllocations() const {
        std::lock_guard<std::mutex> lock(mMutex);

        for (auto allocationEntry : mLiveAllocations) {
            const ResourceAllocation* allocation = allocationEntry->GetValue().GetAllocation();
            gpgmm::WarnEvent(allocation->GetAllocator()->GetTypename())
                << "Live ResourceAllocation at " << ToHexStr(allocation) << ", "
                << JSONSerializer::Serialize(allocation->GetInfo()).ToString();
        }
    }

    void DebugResourceAllocator::AddLiveAllocation(ResourceAllocation* allocation) {
        std::lock_guard<std::mutex> lock(mMutex);

        mLiveAllocations.GetOrCreate(
            ResourceAllocationEntry(allocation, allocation->GetAllocator()), true);

        // Inject |this| allocator so DeallocateMemory shrinks the cache.
        allocation->SetDebugAllocator(this);
    }

    void DebugResourceAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        std::lock_guard<std::mutex> lock(mMutex);

        // KeepAlive must be false so |mLiveAllocations| cache will shrink by 1 entry once |entry|
        // falls out of scope below since AddLiveAllocation() adds one (and only one) ref.
        auto entry = mLiveAllocations.GetOrCreate(
            ResourceAllocationEntry(ToBackend(allocation.get())), false);

        entry->Unref();
        ASSERT(entry->HasOneRef());

        entry->GetValue().GetAllocator()->DeallocateMemory(std::move(allocation));
    }

    const char* DebugResourceAllocator::GetTypename() const {
        return "DebugResourceAllocator";
    }

}  // namespace gpgmm::d3d12
