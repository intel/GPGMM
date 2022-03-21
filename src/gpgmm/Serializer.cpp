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

#include "gpgmm/Serializer.h"

#include "gpgmm/Allocator.h"
#include "gpgmm/Debug.h"
#include "gpgmm/MemoryAllocator.h"
#include "gpgmm/MemoryPool.h"
#include "gpgmm/common/Utils.h"

namespace gpgmm {

    // static
    JSONDict Serializer::Serialize(const POOL_INFO& info) {
        JSONDict dict;
        dict.AddItem("PoolSizeInBytes", info.PoolSizeInBytes);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const LOG_MESSAGE& desc) {
        JSONDict dict;
        dict.AddItem("Description", desc.Description);
        dict.AddItem("ID", desc.ID);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(const MEMORY_ALLOCATOR_INFO& info) {
        JSONDict dict;
        dict.AddItem("UsedBlockCount", info.UsedBlockCount);
        dict.AddItem("UsedMemoryCount", info.UsedMemoryCount);
        dict.AddItem("UsedBlockUsage", info.UsedBlockUsage);
        dict.AddItem("FreeMemoryUsage", info.FreeMemoryUsage);
        dict.AddItem("UsedMemoryUsage", info.UsedMemoryUsage);
        return dict;
    }

    // static
    JSONDict Serializer::Serialize(void* objectPtr) {
        JSONDict dict;
        dict.AddItem(TraceEventID::kIdRefKey, ToString(objectPtr));
        return dict;
    }

}  // namespace gpgmm
